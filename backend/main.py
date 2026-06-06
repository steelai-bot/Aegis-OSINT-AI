import os
import subprocess
import asyncio
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Aegis OSINT API")

# Setup CORS for the React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    target: str
    target_type: str  # 'email', 'phone', 'username'

@app.post("/api/scan")
async def start_scan(request: ScanRequest):
    if request.target_type == "email":
        # Run holehe for email OSINT
        # Running as a subprocess to capture its output directly
        try:
            process = await asyncio.create_subprocess_exec(
                "python", "-m", "holehe", request.target, "--only-used", "--no-color",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            output = stdout.decode('utf-8')
            
            # Parse simple results (just lines that show positive hits)
            hits = []
            for line in output.split('\n'):
                if '[+]' in line:
                    service_name = line.split('[+]')[1].strip()
                    hits.append(service_name)
                    
            return {
                "status": "success",
                "target": request.target,
                "type": request.target_type,
                "exposures": hits,
                "raw_log": output
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
            
    elif request.target_type == "username":
        # E.g. sherlock or similar, currently just a placeholder for the real tool
        return {"status": "success", "target": request.target, "exposures": []}
        
    else:
        raise HTTPException(status_code=400, detail="Unsupported target type")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
