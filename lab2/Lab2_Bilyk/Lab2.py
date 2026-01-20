import time
import statistics as stats
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA

def bench(label, func, repeats=50, bytes_size=None, calc_cv=False):
    times = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        func()
        t1 = time.perf_counter()
        times.append(t1 - t0)
    avg = sum(times) / len(times)
    mn = min(times)
    mx = max(times)
    speed = None
    if bytes_size is not None:
        mb = bytes_size / (1024 * 1024)
        speed = mb / avg if avg > 0 else 0.0

    cv = None
    if calc_cv and len(times) >= 2 and avg > 0:
        stdev = stats.stdev(times)
        cv = (stdev / avg) * 100.0

    out = f"{label}: avg={avg:.6f}s, min={mn:.6f}s, max={mx:.6f}s"
    if speed is not None:
        out += f", speed={speed:.2f} MB/s"
    if cv is not None:
        out += f", CV={cv:.2f}%"

    print(out)
    return times



bench("get_random_bytes(4KB)", lambda: get_random_bytes(4096), bytes_size=4096)
bench("get_random_bytes(1MB)", lambda: get_random_bytes(1024*1024), bytes_size=1024*1024)
bench("get_random_bytes(10MB)", lambda: get_random_bytes(1024*1024*10), bytes_size=1024*1024*10)

bench("\nRSA 1024", lambda: RSA.generate(1024), calc_cv=True)
bench("RSA 2048", lambda: RSA.generate(2048), calc_cv=True)
bench("RSA 4096", lambda: RSA.generate(4096), calc_cv=True)