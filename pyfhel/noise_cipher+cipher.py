import Pyfhel
import numpy as np
import time
import csv
from datetime import datetime
import os

class NoiseBudgetCTPlusCT:
    def __init__(self):
        self.results = []
        self.experiment_name = "Noise_Budget_CT_Plus_CT"
        
    def get_modulus_chains(self):
        return {
            1024: [40, 30, 30, 40],
            2048: [50, 40, 40, 50],
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
    
    def test_ct_plus_ct_operations(self, HE, initial_arr, poly_degree):
        try:
            ptxt1 = HE.encodeInt(initial_arr)
            ptxt2 = HE.encodeInt(initial_arr)
            ctxt1 = HE.encryptPtxt(ptxt1)
            ctxt2 = HE.encryptPtxt(ptxt2)
            
            operation_data = []
            current_ctxt = ctxt1.copy()
            
            # Power of 2 sequence up to 16384
            power_sequence = [2**i for i in range(0, 15) if 2**i <= 16384]
            
            print(f"    Testing power sequence: {power_sequence}")
            
            for target_ops in power_sequence:
                if target_ops == 1:
                    # First operation
                    current_ctxt = ctxt1 + ctxt2
                    ops_done = 1
                else:
                    # Continue from previous
                    prev_ops = power_sequence[power_sequence.index(target_ops) - 1]
                    ops_to_do = target_ops - prev_ops
                    
                    for i in range(ops_to_do):
                        current_ctxt = current_ctxt + ctxt2
                    ops_done = target_ops
                
                # Check if we can still decrypt correctly
                try:
                    result = HE.decryptInt(current_ctxt)
                    expected = (initial_arr * (ops_done + 1)) % HE.t
                    correct = np.array_equal(result[:len(initial_arr)], expected[:len(initial_arr)])
                    
                    # Estimate noise budget progression
                    # Addition operations consume very little noise
                    # We'll track the progression until failure
                    noise_budget_remaining = "OPERATIONAL" if correct else "FAILED"
                    
                except Exception as e:
                    correct = False
                    noise_budget_remaining = "FAILED"
                
                operation_data.append({
                    'operations': ops_done,
                    'noise_budget_status': noise_budget_remaining
                })
                
                print(f"      Operations: {ops_done:5d} | Status: {noise_budget_remaining}")
                
                if not correct:
                    break
                    
            return operation_data
            
        except Exception as e:
            print(f"      ERROR: {e}")
            return []
    
    def run_experiment(self):
        poly_modulus_degrees = [1024, 2048, 4096, 8192, 16384, 32768]
        modulus_chains = self.get_modulus_chains()
        
        print(f"Starting Experiment: {self.experiment_name}")
        print("Testing NOISE BUDGET for CIPHERTEXT + CIPHERTEXT")
        print("Operations in power-of-2 sequence (cap: 16384)")
        print("=" * 80)
        
        for poly_degree in poly_modulus_degrees:
            print(f"\nTesting with polynomial modulus degree: {poly_degree}")
            qi_sizes = modulus_chains[poly_degree]
            total_modulus_bits = sum(qi_sizes)
            
            print(f"  Modulus chain: {qi_sizes}")
            print(f"  Total modulus bits: {total_modulus_bits}")
            
            try:
                HE, t = self.generate_context(poly_degree, qi_sizes)
                vector_size = min(16, poly_degree)
                initial_arr = np.array([2] * vector_size, dtype=np.int64)
                
                operation_data = self.test_ct_plus_ct_operations(HE, initial_arr, poly_degree)
                
                # Log results
                for data in operation_data:
                    result_row = {
                        'poly_degree': poly_degree,
                        'total_modulus_bits': total_modulus_bits,
                        'modulus_chain': str(qi_sizes),
                        'operation_type': 'ct_plus_ct',
                        'operations_count': data['operations'],
                        'noise_budget_status': data['noise_budget_status'],
                        'plaintext_modulus': t
                    }
                    self.results.append(result_row)
                
                del HE
                
            except Exception as e:
                print(f"  ERROR: {e}")
        
        self.save_results_to_csv()
        
    def save_results_to_csv(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.experiment_name}_{timestamp}.csv"
        os.makedirs("experiment_results", exist_ok=True)
        filepath = os.path.join("experiment_results", filename)
        
        fieldnames = [
            'poly_degree', 'total_modulus_bits', 'modulus_chain',
            'operation_type', 'operations_count', 'noise_budget_status',
            'plaintext_modulus'
        ]
        
        with open(filepath, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for result in self.results:
                writer.writerow(result)
        
        print(f"\nResults saved to: {filepath}")

def main_noise_budget_ct_plus_ct():
    experiment = NoiseBudgetCTPlusCT()
    experiment.run_experiment()
    print("Noise Budget CT+CT Experiment completed!")

if __name__ == "__main__":
    main_noise_budget_ct_plus_ct()
