import Pyfhel
import numpy as np
import time
import csv
from datetime import datetime
import os

class CipherTimesCipherExperiment:
    def __init__(self):
        self.results = []
        self.experiment_name = "Cipher_Times_Cipher_Experiment"
        
    def get_modulus_chains(self):
        """Define modulus chains for different polynomial degrees"""
        return {
            1024: [40, 30, 30, 40],  # Increased for key switching
            2048: [50, 40, 40, 50],   # Increased for key switching
            4096: [50, 30, 30, 30, 50],
            8192: [60, 40, 40, 40, 60],
            16384: [60, 40, 40, 40, 40, 60],
            32768: [60, 40, 40, 40, 40, 40, 60]
        }
    
    def generate_context(self, poly_degree, qi_sizes):
        """Generate HE context with given parameters"""
        HE = Pyfhel.Pyfhel()
        
        # Plaintext modulus
        if poly_degree == 1024:
            t = 65537
        elif poly_degree == 2048:
            t = 65537
        elif poly_degree == 4096:
            t = 65537
        elif poly_degree == 8192:
            t = 65537
        elif poly_degree == 16384:
            t = 132120577
        elif poly_degree == 32768:
            t = 265420801
        else:
            t = 65537
            
        HE.contextGen(
            scheme='bfv',
            n=poly_degree,
            t=t,
            sec=128,
            qi_sizes=qi_sizes
        )
        HE.keyGen()
        
        # Generate rotation and relin keys - required for ciphertext multiplication
        try:
            HE.rotateKeyGen()
            HE.relinKeyGen()
        except Exception as e:
            print(f"    Key generation warning: {e}")
            
        return HE, t
    
    def test_cipher_times_cipher_operations(self, HE, initial_arr):
        """Test maximum ciphertext × ciphertext operations"""
        try:
            # Create initial ciphertexts
            ptxt = HE.encodeInt(initial_arr)
            ctxt1 = HE.encryptPtxt(ptxt)
            ctxt2 = HE.encryptPtxt(ptxt)
            
            operation_count = 0
            
            # Keep multiplying until failure
            while True:
                ctxt1 = ctxt1 * ctxt2
                
                # Try to relinearize if possible
                try:
                    HE.relinearize(ctxt1)
                except:
                    pass  # Continue without relinearization
                    
                operation_count += 1
                
                # Verify we can still decrypt correctly
                try:
                    result = HE.decryptInt(ctxt1)
                    expected = (initial_arr ** (operation_count + 1)) % HE.t
                    
                    # Check if results match (within tolerance for larger exponents)
                    if not np.array_equal(result[:len(initial_arr)], expected[:len(initial_arr)]):
                        print(f"      Result mismatch after {operation_count} operations")
                        break
                        
                except Exception as e:
                    print(f"      Decryption failed after {operation_count} operations: {e}")
                    break
                    
            return operation_count
            
        except Exception as e:
            print(f"      Failed after {operation_count} operations: {e}")
            return operation_count
    
    def run_experiment(self):
        """Run the cipher × cipher experiment"""
        poly_modulus_degrees = [1024, 2048, 4096, 8192, 16384, 32768]
        modulus_chains = self.get_modulus_chains()
        
        print(f"Starting Experiment: {self.experiment_name}")
        print(f"Testing MAXIMUM CIPHERTEXT × CIPHERTEXT OPERATIONS")
        print("=" * 80)
        
        for poly_degree in poly_modulus_degrees:
            print(f"\nTesting with polynomial modulus degree: {poly_degree}")
            
            qi_sizes = modulus_chains[poly_degree]
            total_modulus_bits = sum(qi_sizes)
            
            print(f"  Modulus chain: {qi_sizes}")
            print(f"  Total modulus bits: {total_modulus_bits}")
            
            try:
                HE, t = self.generate_context(poly_degree, qi_sizes)
                
                # Generate test data (use small numbers to avoid overflow)
                vector_size = min(8, poly_degree)  # Smaller vector for stability
                initial_arr = np.array([2] * vector_size, dtype=np.int64)
                
                # Test maximum operations
                max_operations = self.test_cipher_times_cipher_operations(HE, initial_arr)
                
                # Log results
                result_row = {
                    'poly_degree': poly_degree,
                    'total_modulus_bits': total_modulus_bits,
                    'modulus_chain': str(qi_sizes),
                    'max_operations': max_operations,
                    'plaintext_modulus': t,
                    'operation_type': 'cipher_times_cipher'
                }
                
                self.results.append(result_row)
                print(f"  Maximum CT×CT operations: {max_operations}")
                
                del HE
                
            except Exception as e:
                print(f"  ERROR: {e}")
                result_row = {
                    'poly_degree': poly_degree,
                    'total_modulus_bits': total_modulus_bits,
                    'modulus_chain': str(qi_sizes),
                    'max_operations': 0,
                    'plaintext_modulus': 0,
                    'operation_type': 'cipher_times_cipher',
                    'error': str(e)
                }
                self.results.append(result_row)
        
        self.save_results_to_csv()
        
    def save_results_to_csv(self):
        """Save results to CSV"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.experiment_name}_{timestamp}.csv"
        
        os.makedirs("experiment_results", exist_ok=True)
        filepath = os.path.join("experiment_results", filename)
        
        fieldnames = [
            'poly_degree',
            'total_modulus_bits',
            'modulus_chain',
            'max_operations',
            'plaintext_modulus',
            'operation_type',
            'error'  # Added error field
        ]
        
        with open(filepath, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for result in self.results:
                # Fill missing fields with empty values
                row = {field: result.get(field, '') for field in fieldnames}
                writer.writerow(row)
        
        print(f"\nResults saved to: {filepath}")
        
    def generate_summary(self):
        """Generate a summary of the experiment results"""
        if not self.results:
            print("No results to summarize")
            return
        
        print(f"\n{'='*80}")
        print(f"EXPERIMENT SUMMARY - CIPHERTEXT × CIPHERTEXT OPERATIONS")
        print(f"{'='*80}")
        
        for result in self.results:
            if result.get('max_operations', 0) > 0:
                print(f"Poly Degree {result['poly_degree']}: {result['max_operations']} operations")
            else:
                print(f"Poly Degree {result['poly_degree']}: FAILED - {result.get('error', 'Unknown error')}")

def main_cipher_times_cipher():
    experiment = CipherTimesCipherExperiment()
    experiment.run_experiment()
    experiment.generate_summary()
    print("Cipher × Cipher Experiment completed!")

if __name__ == "__main__":
    main_cipher_times_cipher()
