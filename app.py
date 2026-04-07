import os
import json
import uuid
import asyncio
import subprocess
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="WebProbe API")

# Production: Serve React Frontend
if os.path.exists("./frontend/dist"):
    app.mount("/assets", StaticFiles(directory="./frontend/dist/assets"), name="assets")
    
    @app.get("/", include_in_schema=False)
    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_react(full_path: str = ""):
        # If the path looks like an API call, let it through
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404)
        return FileResponse("./frontend/dist/index.html")
else:
    @app.get("/")
    async def root():
        return {"status": "WebProbe API is online (Manual UI build required)", "stream_endpoint": "/api/scan/stream"}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Routes continue below...

@app.get("/api/scan/stream")
async def stream_scan(url: str, depth: int = 1, threads: int = 10, skip_dirs: bool = True):
    if not (url.startswith("http://") or url.startswith("https://")):
        async def err(): yield f"data: [ERROR] Invalid URL\n\n"
        return StreamingResponse(err(), media_type="text/event-stream")

    async def event_generator():
        # Using -u to disable python stdout buffering
        cmd = ["python3", "-u", "webprobe.py", url, "--depth", str(depth), "--threads", str(threads)]
        if skip_dirs:
            cmd.append("--skip-dirs")
            
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT
        )
        
        while True:
            line = await process.stdout.readline()
            if not line:
                break
            
            line_str = line.decode('utf-8').rstrip()
            if line_str:
                yield f"data: {line_str}\n\n"
        
        await process.wait()
        yield "data: [WEBPROBE_DONE]\n\n"
        
    return StreamingResponse(event_generator(), media_type="text/event-stream")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8005, reload=True)
