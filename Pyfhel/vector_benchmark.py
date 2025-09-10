import time
import tracemalloc
import csv
import numpy as np
from Pyfhel import Pyfhel

def benchmark_vector():
    # BFV allowed poly degrees
    poly_degrees = [1024, 2048, 4096, 8192, 16384, 32768]
    data_sizes = [10_000, 100_000, 1_000_000]
    t = 65537

    results = []

    def log_result(poly_deg, data_size, op_type, enc_time, op_time, dec_time, mem):
        results.append({
            "poly_modulus_degree": poly_deg,
            "data_size": data_size,
            "operation_type": op_type,
            "enc_time": enc_time,
            "op_time": op_time,
            "dec_time": dec_time,
            "memory_usage": mem
        })

    for poly_degree in poly_degrees:
        HE = Pyfhel()
        HE.contextGen(scheme='BFV', n=poly_degree, t=t)
        HE.keyGen()
        nSlots = HE.get_nSlots()
        chunk_size = nSlots

        for vector_size in data_sizes:
            # Generate random vectors
            A = np.random.randint(0, 100, size=vector_size, dtype=np.int64)
            B = np.random.randint(0, 100, size=vector_size, dtype=np.int64)

            # Helper functions
            def encrypt_chunks(vec):
                enc_chunks = []
                total_enc_time = 0
                total_mem = 0
                for i in range(0, len(vec), chunk_size):
                    chunk = vec[i:i+chunk_size]
                    tracemalloc.start()
                    t0 = time.time()
                    enc_chunk = HE.encryptInt(chunk)
                    enc_time = time.time() - t0
                    mem = tracemalloc.get_traced_memory()[1]
                    tracemalloc.stop()
                    enc_chunks.append(enc_chunk)
                    total_enc_time += enc_time
                    total_mem = max(total_mem, mem)
                return enc_chunks, total_enc_time, total_mem

            def decrypt_chunks(enc_chunks):
                dec_vec = []
                total_dec_time = 0
                for enc_chunk in enc_chunks:
                    t0 = time.time()
                    dec_chunk = HE.decryptInt(enc_chunk)
                    dec_time = time.time() - t0
                    dec_vec.extend(dec_chunk)
                    total_dec_time += dec_time
                return np.array(dec_vec), total_dec_time

            def homomorphic_op(enc_X, enc_Y, op_type):
                res_chunks = []
                t0 = time.time()
                for x_chunk, y_chunk in zip(enc_X, enc_Y):
                    if op_type.endswith("add"):
                        res_chunks.append(x_chunk + y_chunk)
                    else:
                        res_chunks.append(x_chunk * y_chunk)
                op_time = time.time() - t0
                dec_res, dec_time = decrypt_chunks(res_chunks)
                return op_time, dec_time

            # Encrypt vectors
            enc_A, enc_time_A, mem_A = encrypt_chunks(A)
            enc_B, enc_time_B, mem_B = encrypt_chunks(B)

            # 1. Plain + Plain
            t0 = time.time(); res = A + B; op_time = time.time() - t0
            log_result(poly_degree, vector_size, "PP_add", 0, op_time, 0, 0)

            t0 = time.time(); res = A * B; op_time = time.time() - t0
            log_result(poly_degree, vector_size, "PP_mul", 0, op_time, 0, 0)

            # 2. Plain + Cipher
            op_time, dec_time = homomorphic_op(enc_A, enc_B, "PC_add")
            log_result(poly_degree, vector_size, "PC_add", enc_time_A, op_time, dec_time, mem_A)

            op_time, dec_time = homomorphic_op(enc_A, enc_B, "PC_mul")
            log_result(poly_degree, vector_size, "PC_mul", enc_time_A, op_time, dec_time, mem_A)

            # 3. Cipher + Plain
            op_time, dec_time = homomorphic_op(enc_A, enc_B, "CP_add")
            log_result(poly_degree, vector_size, "CP_add", enc_time_B, op_time, dec_time, mem_B)

            op_time, dec_time = homomorphic_op(enc_A, enc_B, "CP_mul")
            log_result(poly_degree, vector_size, "CP_mul", enc_time_B, op_time, dec_time, mem_B)

            # 4. Cipher + Cipher
            op_time, dec_time = homomorphic_op(enc_A, enc_B, "CC_add")
            log_result(poly_degree, vector_size, "CC_add", 0, op_time, dec_time, max(mem_A, mem_B))

            op_time, dec_time = homomorphic_op(enc_A, enc_B, "CC_mul")
            log_result(poly_degree, vector_size, "CC_mul", 0, op_time, dec_time, max(mem_A, mem_B))

    # Save results
    with open("vector_benchmark_full.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    print("Vector benchmark for all poly degrees and data sizes completed. Results saved to vector_benchmark_full.csv")

if __name__ == "__main__":
    benchmark_vector()
