import asyncio
import websockets
import json

async def test_ws():
    uri = "ws://127.0.0.1:8000/ws/live-capture"
    try:
        async with websockets.connect(uri) as websocket:
            print("Connected to WebSocket")
            # Wait for messages for a few seconds
            for _ in range(5):
                message = await asyncio.wait_for(websocket.recv(), timeout=15.0)
                print(f"Received: {json.loads(message)}")
    except asyncio.TimeoutError:
        print("Timeout waiting for message")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(test_ws())
