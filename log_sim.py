import random
import time
from datetime import datetime

# Realistic OT log templates
NORMAL_LOGS = [
    "Modbus TCP READ_HOLDING_REGISTERS unit=1 addr=100 count=10 status=OK",
    "DNP3 ANALOG_INPUT obj=30 point=5 value=72.4 quality=ONLINE",
    "SCADA HMI_LOGIN user=operator1 station=HMI-01 status=SUCCESS",
    "PLC COIL_WRITE unit=2 addr=200 value=1 status=OK",
    "Syslog INFO Fieldbus heartbeat device=RTU-03 latency=12ms",
    "DNP3 BINARY_OUTPUT obj=12 point=2 value=OFF status=OK",
    "Modbus TCP WRITE_SINGLE_REGISTER unit=3 addr=300 value=450 status=OK",
]

ANOMALY_LOGS = [
    # Reconnaissance — scanning
    ("Modbus TCP READ_HOLDING_REGISTERS unit=255 addr=0 count=125 status=OK src=192.168.1.99",
     "RECONNAISSANCE", "Network Service Scanning (T0846)"),

    # Brute force login
    ("SCADA HMI_LOGIN user=admin station=REMOTE-99 status=FAILED attempt=15",
     "BRUTE_FORCE", "Brute Force I/O (T0806)"),

    # Unexpected write to critical register
    ("Modbus TCP WRITE_MULTIPLE_REGISTERS unit=1 addr=500 count=50 src=UNKNOWN status=OK",
     "UNAUTHORIZED_WRITE", "Modify Control Logic (T0833)"),

    # Out-of-range sensor value (process anomaly)
    ("DNP3 ANALOG_INPUT obj=30 point=5 value=9999.9 quality=ONLINE",
     "SENSOR_SPIKE", "Manipulation of Control (T0831)"),

    # Unexpected device appearing on network
    ("Syslog WARN New device detected MAC=DE:AD:BE:EF:00:01 IP=192.168.2.200 port=502",
     "ROGUE_DEVICE", "Remote System Discovery (T0846)"),

    # Rapid coil toggling (could signal relay attack)
    ("PLC COIL_WRITE unit=1 addr=200 value=1 status=OK count=47 interval=0.1s",
     "RAPID_TOGGLE", "Activate Firmware Update Mode (T0800)"),
]

def generate_log_stream(output_file="ot_simulation.log", duration_seconds=3600):
    """Generates a realistic OT log stream with occasional anomalies."""
    print(f"Simulating OT logs → {output_file}")
    with open(output_file, "a") as f:
        start = time.time()
        while time.time() - start < duration_seconds:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

            # 10% chance of anomaly
            if random.random() < 0.10:
                log, anomaly_type, attack = random.choice(ANOMALY_LOGS)
                line = f"[{timestamp}] ⚠ {log}\n"
                print(f"INJECTING ANOMALY: {anomaly_type}")
            else:
                log = random.choice(NORMAL_LOGS)
                line = f"[{timestamp}] {log}\n"

            f.write(line)
            f.flush()
            time.sleep(random.uniform(0.3, 1.2))  # Realistic timing

if __name__ == "__main__":
    generate_log_stream()
