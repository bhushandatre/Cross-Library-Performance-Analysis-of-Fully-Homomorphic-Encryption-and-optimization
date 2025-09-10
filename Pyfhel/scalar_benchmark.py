import time
import tracemalloc
import csv
import numpy as np
from Pyfhel import Pyfhel

def benchmark_scalar(poly_degrees=[1024, 2048, 4096, 8192, 16384], scalars=[1, 7, 42, 123]):
    results = []

    def log_result(poly_deg, scalar_a, scalar_b, op_type, enc_time, op_time, dec_time, mem):
        results.append({
            "poly_modulus_degree": poly_deg,
            "scalar_a": scalar_a,
            "scalar_b": scalar_b,
            "operation_type": op_type,
            "enc_time": enc_time,
            "op_time": op_time,
            "dec_time": dec_time,
            "memory_usage": mem
        })

    for poly_degree in poly_degrees:
        HE = Pyfhel()
        HE.contextGen(scheme='BFV', n=poly_degree, t=65537)
        HE.keyGen()

        for scalar_a in scalars:
            for scalar_b in scalars:
                a = np.array([scalar_a], dtype=np.int64)
                b = np.array([scalar_b], dtype=np.int64)

                # Encryption
                tracemalloc.start()
                t0 = time.time(); enc_a = HE.encryptInt(a); enc_time_a = time.time() - t0
                mem_a = tracemalloc.get_traced_memory()[1]

                t0 = time.time(); enc_b = HE.encryptInt(b); enc_time_b = time.time() - t0
                mem_b = tracemalloc.get_traced_memory()[1]
                tracemalloc.stop()

                # Helper function for encrypted operation
                def do_enc_op(enc1, enc2, op_type):
                    tracemalloc.start()
                    t0 = time.time()
                    if op_type.endswith("add"):
                        res = enc1 + enc2
                    else:
                        res = enc1 * enc2
                    op_time = time.time() - t0
                    mem = tracemalloc.get_traced_memory()[1]
                    tracemalloc.stop()
                    t0 = time.time()
                    dec = HE.decryptInt(res)
                    dec_time = time.time() - t0
                    return op_time, dec_time, mem

                # 1. Plain + Plain
                t0 = time.time(); res = a + b; op_time = time.time() - t0
                t0 = time.time(); dec = res; dec_time = time.time() - t0
                log_result(poly_degree, scalar_a, scalar_b, "PP_add", 0, op_time, dec_time, 0)

                t0 = time.time(); res = a * b; op_time = time.time() - t0
                t0 = time.time(); dec = res; dec_time = time.time() - t0
                log_result(poly_degree, scalar_a, scalar_b, "PP_mul", 0, op_time, dec_time, 0)

                # 2. Plain + Cipher
                op_time, dec_time, mem = do_enc_op(HE.encryptInt(a), enc_b, "PC_add")
                log_result(poly_degree, scalar_a, scalar_b, "PC_add", enc_time_a, op_time, dec_time, mem)

                op_time, dec_time, mem = do_enc_op(HE.encryptInt(a), enc_b, "PC_mul")
                log_result(poly_degree, scalar_a, scalar_b, "PC_mul", enc_time_a, op_time, dec_time, mem)

                # 3. Cipher + Plain
                op_time, dec_time, mem = do_enc_op(enc_a, HE.encryptInt(b), "CP_add")
                log_result(poly_degree, scalar_a, scalar_b, "CP_add", enc_time_b, op_time, dec_time, mem)

                op_time, dec_time, mem = do_enc_op(enc_a, HE.encryptInt(b), "CP_mul")
                log_result(poly_degree, scalar_a, scalar_b, "CP_mul", enc_time_b, op_time, dec_time, mem)

                # 4. Cipher + Cipher
                op_time, dec_time, mem = do_enc_op(enc_a, enc_b, "CC_add")
                log_result(poly_degree, scalar_a, scalar_b, "CC_add", 0, op_time, dec_time, mem)

                op_time, dec_time, mem = do_enc_op(enc_a, enc_b, "CC_mul")
                log_result(poly_degree, scalar_a, scalar_b, "CC_mul", 0, op_time, dec_time, mem)

    # Save to CSV
    with open("scalar_benchmark_full.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    print("Scalar benchmark for all poly degrees and scalar sizes completed. Results saved to scalar_benchmark_full.csv")

if __name__ == "__main__":
    benchmark_scalar()
