import Pyfhel
import numpy as np
import time
import csv
from datetime import datetime
import os

class CipherTimesPlainExperiment:
    def __init__(self):
        self.results = []
        self.experiment_name = "Cipher_Times_Plain_Experiment"
        
    def get_modulus_chains(self):
        return {
            1024: [30, 20, 20, 30],
            2048: [40, 30, 30, 40],
            4096: [50, 30, 30, 30, 50],
            8192: [60, 40, 40, 40, 60],
            16384: [60, 40, 40, 40, 40, 60],
            32768: [60, 40, 40, 40, 40, 40, 60]
        }
    
    def generate_context(self, poly_degree, qi_sizes):
        HE = Pyfhel.Pyfhel()
        
        if poly_degree == 1024: t = 65537
        elif poly_degree == 2048: t = 65537
        elif poly_degree == 4096: t = 65537
        elif poly_degree == 8192: t = 65537
        elif poly_degree == 16384: t = 132120577
        elif poly_degree == 32768: t = 265420801
        else: t = 65537
            
        HE.contextGen(scheme='bfv', n=poly_degree, t=t, sec=128, qi_sizes=qi_sizes)
        HE.keyGen()
        return HE, t
    
    def test_cipher_times_plain_operations(self, HE, initial_arr):
        try:
            ptxt = HE.encodeInt(initial_arr)
            ctxt = HE.encryptPtxt(ptxt)
            operation_count = 0
            
            while True:
                ctxt = ctxt * ptxt
                operation_count += 1
                result = HE.decryptInt(ctxt)
                expected = (initial_arr ** (operation_count + 1)) % HE.t
                if not np.array_equal(result[:len(initial_arr)], expected[:len(initial_arr)]):
                    break
                    
            return operation_count
            
        except Exception as e:
            print(f"      Failed after {operation_count} operations: {e}")
            return operation_count
    
    def run_experiment(self):
        poly_modulus_degrees = [1024, 2048, 4096, 8192, 16384, 32768]
        modulus_chains = self.get_modulus_chains()
        
        print(f"Starting Experiment: {self.experiment_name}")
        print("Testing MAXIMUM CIPHERTEXT × PLAINTEXT OPERATIONS")
        print("=" * 80)
        
        for poly_degree in poly_modulus_degrees:
            print(f"\nTesting with polynomial modulus degree: {poly_degree}")
            qi_sizes = modulus_chains[poly_degree]
            total_modulus_bits = sum(qi_sizes)
            
            print(f"  Modulus chain: {qi_sizes}")
            print(f"  Total modulus bits: {total_modulus_bits}")
            
            try:
                HE, t = self.generate_context(poly_degree, qi_sizes)
                vector_size = min(8, poly_degree)
                initial_arr = np.array([2] * vector_size, dtype=np.int64)
                max_operations = self.test_cipher_times_plain_operations(HE, initial_arr)
                
                result_row = {
                    'poly_degree': poly_degree, 'total_modulus_bits': total_modulus_bits,
                    'modulus_chain': str(qi_sizes), 'max_operations': max_operations,
                    'plaintext_modulus': t, 'operation_type': 'cipher_times_plain'
                }
                self.results.append(result_row)
                print(f"  Maximum CT×PT operations: {max_operations}")
                del HE
                
            except Exception as e:
                print(f"  ERROR: {e}")
                result_row = {
                    'poly_degree': poly_degree, 'total_modulus_bits': total_modulus_bits,
                    'modulus_chain': str(qi_sizes), 'max_operations': 0,
                    'plaintext_modulus': 0, 'operation_type': 'cipher_times_plain', 'error': str(e)
                }
                self.results.append(result_row)
        
        self.save_results_to_csv()
        
    def save_results_to_csv(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.experiment_name}_{timestamp}.csv"
        os.makedirs("experiment_results", exist_ok=True)
        filepath = os.path.join("experiment_results", filename)
        
        fieldnames = ['poly_degree', 'total_modulus_bits', 'modulus_chain', 'max_operations', 'plaintext_modulus', 'operation_type', 'error']
        
        with open(filepath, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for result in self.results:
                row = {field: result.get(field, '') for field in fieldnames}
                writer.writerow(row)
        
        print(f"\nResults saved to: {filepath}")

def main_cipher_times_plain():
    experiment = CipherTimesPlainExperiment()
    experiment.run_experiment()
    print("Cipher × Plain Experiment completed!")

if __name__ == "__main__":
    main_cipher_times_plain()
