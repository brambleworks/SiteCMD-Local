import asyncio
import base64
import importlib
import json
import os
import sys

channel = os.fdopen(int(sys.argv[1]), "w", buffering=1)
sys.path.insert(0, "/work")


def send(value):
    channel.write(json.dumps(value) + "\n")


class ContextSentinel(Exception):
    pass


async def main():
    try:
        module = importlib.import_module("src.network.client")
        send({"ready": True})
    except Exception as error:
        send({"ready": False, "error": f"{type(error).__name__}: {error}"})
        return
    client = None
    for line in sys.stdin:
        job = json.loads(line)
        reply = {"id": job["id"]}
        try:
            operation = job["operation"]
            if operation == "new":
                client = module.HttpClient()
                reply["ready"] = True
            elif operation == "exceptional-context":
                client = module.HttpClient()
                try:
                    async with client:
                        raise ContextSentinel("context body failed")
                except ContextSentinel:
                    reply["propagated"] = True
                else:
                    reply["propagated"] = False
            elif operation == "enter":
                reply["sameClient"] = await client.__aenter__() is client
            elif operation == "exit":
                await client.__aexit__(None, None, None)
                reply["closed"] = True
            elif operation == "close":
                await client.close()
                reply["closed"] = True
            elif operation in ("get", "post", "concurrent"):
                async def request(url):
                    if operation == "post":
                        response = await client._client.post(url, json=job["data"], headers=job["headers"])
                    else:
                        response = await client.get(url, job.get("headers"))
                    return {"status": response.status_code, "body": base64.b64encode(response.content).decode(),
                            "timeout": response.request.extensions.get("timeout")}
                if operation == "concurrent":
                    reply["responses"] = await asyncio.gather(*(request(url) for url in job["urls"]))
                else:
                    reply["response"] = await request(job["url"])
            else:
                raise ValueError("Unknown operation")
        except Exception as error:
            reply.update(error=str(error), errorType=type(error).__name__)
        send(reply)


asyncio.run(main())
