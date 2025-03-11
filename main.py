#!/home/nav/main_project/anomalyX/.env/bin/python

from backend.model.model import NetworkArchitecture
from backend.network.parse_main import NetworkFeatureExtractor
from live_data_preprocess import LiveDataPreprocessor
import time
import pandas as pd
import numpy as np
import threading
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi_socketio import SocketManager
import asyncio

extractor = NetworkFeatureExtractor(time_window=2, batch_size=10)

preprocessor = LiveDataPreprocessor()

app = FastAPI()
socket_manager = SocketManager(app=app)
app.add_middleware(CORSMiddleware, allow_origins=["*"])


@app.on_event("startup")
async def startup_event():
    extractor.start_capture(interface="s1-eth1", continuous=True)
    asyncio.create_task(continuous_processing())


async def continuous_processing():
    while True:
        df_batch = extractor.get_features_batch(timeout=1.0)

        if df_batch is not None and df_batch is not df_batch.empty:
            try:
                original_data = df_batch.copy()

                preprocessor.fit(df_batch)
                processed_data = preprocessor.transform(df_batch)


                input_shape = (processed_data.shape[1], ) 
                num_classes = 5
                
                model = NetworkArchitecture.build_cnn_model(input_shape, num_classes)
                model.load_weights('best_model.h5')


                predictions = model.predict(processed_data)
                original_data['anomaly_score'] = predictions.mean(axis=1)
                print(original_data['anomaly_score'])
                original_data['is_anomaly'] = original_data['anomaly_score'] > 0.4

                await socket_manager.emit('anomaly_updates', {
                    'timestamp': pd.Timestamp.now().isoformat(),
                    'data': original_data.to_dict('records'),
                    'anomaly_count': int(original_data['is_anomaly'].sum()),
                    'total_count': len(original_data)
                })
                print("succes")
                print(f"✓ Processed batch with {len(original_data)} packets, found {original_data['is_anomaly'].sum()} anomalies")
                
            except Exception as e:
                print(f"Error processing batch: {e}")
        
        await asyncio.sleep(0.1)

@app.get("/api/status")
async def check_status():
    return {
        "status": "active", 
        "packets_in_queue": extractor.feature_queue.qsize(),
        "uptime": "running"
    }

@app.on_event("shutdown")
async def shutdown_event():
    extractor.stop()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
