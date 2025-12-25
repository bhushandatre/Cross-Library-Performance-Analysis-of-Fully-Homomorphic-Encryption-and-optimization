import Pyfhel
import numpy as np
import time
import csv
from datetime import datetime
import os
import math

class SameNumberExperiment:
    def __init__(self):
        self.results = []
        self.experiment_name = "Same_Number_Experiment"
        
    def generate_context(self, poly_modulus_degree):
        """Generate HE context with given polynomial modulus degree"""
        HE = Pyfhel.Pyfhel()
        
        # For BFV scheme with batching
        if poly_modulus_degree == 4096:
            t = 65537
        elif poly_modulus_degree == 8192:
            t = 65537
        elif poly_modulus_degree == 16384:
            t = 132120577
        elif poly_modulus_degree == 32768:
            t = 265420801
        else:
            t = 65537
            
        HE.contextGen(scheme='bfv', n=poly_modulus_degree, t=t, sec=128)
        HE.keyGen()
        HE.relinKeyGen()
        
        return HE
    
    def generate_same_number_data(self, vector_size, max_value=1000):
        """Generate test data with same number in all slots"""
        value = np.random.randint(1, max_value)
        arr1 = np.array([value] * vector_size, dtype=np.int64)
        arr2 = np.array([value] * vector_size, dtype=np.int64)
        
        print(f"    Using same number: {value} in all {vector_size} slots")
        return arr1, arr2
    
    def split_vector(self, vector, max_slots):
        """Split a large vector into chunks that fit in available slots"""
        chunks = []
        num_chunks = math.ceil(len(vector) / max_slots)
        
        for i in range(num_chunks):
            start_idx = i * max_slots
            end_idx = min((i + 1) * max_slots, len(vector))
            chunk = vector[start_idx:end_idx]
            
            # Pad with zeros if needed to fill all slots
            if len(chunk) < max_slots:
                chunk = np.pad(chunk, (0, max_slots - len(chunk)), mode='constant')
            
            chunks.append(chunk)
        
        return chunks
    
    def run_operation_tests(self, HE, arr1, arr2, vector_size, poly_degree, operation):
        """Run specific operation and measure times"""
        
        max_slots = poly_degree
        
        # If vector fits in one ciphertext
        if vector_size <= max_slots:
            return self._run_single_ciphertext_operation(HE, arr1, arr2, vector_size, poly_degree, operation)
        else:
            return self._run_multi_ciphertext_operation(HE, arr1, arr2, vector_size, poly_degree, operation)
    
    def _run_single_ciphertext_operation(self, HE, arr1, arr2, vector_size, poly_degree, operation):
        """Run operation when vector fits in single ciphertext"""
        try:
            # Pad arrays to fill all slots if needed
            if len(arr1) < poly_degree:
                arr1_padded = np.pad(arr1, (0, poly_degree - len(arr1)), mode='constant')
                arr2_padded = np.pad(arr2, (0, poly_degree - len(arr2)), mode='constant')
            else:
                arr1_padded = arr1
                arr2_padded = arr2
            
            if operation == "cipher_plus_cipher":
                # Encryption
                start_time = time.time()
                ptxt1 = HE.encodeInt(arr1_padded)
                ptxt2 = HE.encodeInt(arr2_padded)
                ctxt1 = HE.encryptPtxt(ptxt1)
                ctxt2 = HE.encryptPtxt(ptxt2)
                encryption_time = time.time() - start_time
                
                # Operation
                start_time = time.time()
                ctxt_result = ctxt1 + ctxt2
                operation_time = time.time() - start_time
                
            elif operation == "cipher_times_plain":
                # Encryption
                start_time = time.time()
                ptxt1 = HE.encodeInt(arr1_padded)
                ptxt2 = HE.encodeInt(arr2_padded)
                ctxt1 = HE.encryptPtxt(ptxt1)
                encryption_time = time.time() - start_time
                
                # Operation
                start_time = time.time()
                ctxt_result = ctxt1 * ptxt2
                operation_time = time.time() - start_time
                
            elif operation == "cipher_plus_plain":
                # Encryption
                start_time = time.time()
                ptxt1 = HE.encodeInt(arr1_padded)
                ptxt2 = HE.encodeInt(arr2_padded)
                ctxt1 = HE.encryptPtxt(ptxt1)
                encryption_time = time.time() - start_time
                
                # Operation
                start_time = time.time()
                ctxt_result = ctxt1 + ptxt2
                operation_time = time.time() - start_time
                
            elif operation == "cipher_times_cipher":
                # Encryption
                start_time = time.time()
                ptxt1 = HE.encodeInt(arr1_padded)
                ptxt2 = HE.encodeInt(arr2_padded)
                ctxt1 = HE.encryptPtxt(ptxt1)
                ctxt2 = HE.encryptPtxt(ptxt2)
                encryption_time = time.time() - start_time
                
                # Operation
                start_time = time.time()
                ctxt_result = ctxt1 * ctxt2
                operation_time = time.time() - start_time
            
            # Decryption
            start_time = time.time()
            result_ptxt = HE.decryptPtxt(ctxt_result)
            result_arr = HE.decodeInt(result_ptxt)
            decryption_time = time.time() - start_time
            
            # Verification
            if operation == "cipher_plus_cipher" or operation == "cipher_plus_plain":
                expected = (arr1 + arr2) % HE.t
            else:  # multiplication operations
                expected = (arr1 * arr2) % HE.t
            
            correct = np.array_equal(result_arr[:vector_size], expected)
            
            # Log result
            result_row = {
                'poly_degree': poly_degree,
                'vector_size': vector_size,
                'operation': operation,
                'encryption_time': encryption_time,
                'operation_time': operation_time,
                'decryption_time': decryption_time,
                'total_time': encryption_time + operation_time + decryption_time,
                'correct': correct,
                'num_ciphertexts': 1,
                'data_type': 'same_number'
            }
            
            self.results.append(result_row)
            return True
            
        except Exception as e:
            print(f"    ERROR in {operation}: {e}")
            result_row = {
                'poly_degree': poly_degree,
                'vector_size': vector_size,
                'operation': operation,
                'encryption_time': None,
                'operation_time': None,
                'decryption_time': None,
                'total_time': None,
                'correct': False,
                'num_ciphertexts': 1,
                'data_type': 'same_number'
            }
            self.results.append(result_row)
            return False
    
    def _run_multi_ciphertext_operation(self, HE, arr1, arr2, vector_size, poly_degree, operation):
        """Run operation when vector requires multiple ciphertexts"""
        try:
            max_slots = poly_degree
            num_ciphertexts = math.ceil(vector_size / max_slots)
            
            # Split vectors into chunks
            arr1_chunks = self.split_vector(arr1, max_slots)
            arr2_chunks = self.split_vector(arr2, max_slots)
            
            # Encryption time
            encryption_time = 0
            ciphertexts1 = []
            ciphertexts2 = []
            plaintexts2 = []
            
            # Encrypt all chunks
            for i in range(num_ciphertexts):
                start_time = time.time()
                ptxt1 = HE.encodeInt(arr1_chunks[i])
                ptxt2 = HE.encodeInt(arr2_chunks[i])
                
                if operation in ["cipher_plus_cipher", "cipher_times_cipher"]:
                    ctxt1 = HE.encryptPtxt(ptxt1)
                    ctxt2 = HE.encryptPtxt(ptxt2)
                    ciphertexts1.append(ctxt1)
                    ciphertexts2.append(ctxt2)
                else:  # operations with plaintext
                    ctxt1 = HE.encryptPtxt(ptxt1)
                    ciphertexts1.append(ctxt1)
                    plaintexts2.append(ptxt2)
                
                encryption_time += time.time() - start_time
            
            # Operation time
            operation_time = 0
            result_ciphertexts = []
            
            start_time = time.time()
            for i in range(num_ciphertexts):
                if operation == "cipher_plus_cipher":
                    result_ctxt = ciphertexts1[i] + ciphertexts2[i]
                elif operation == "cipher_times_plain":
                    result_ctxt = ciphertexts1[i] * plaintexts2[i]
                elif operation == "cipher_plus_plain":
                    result_ctxt = ciphertexts1[i] + plaintexts2[i]
                elif operation == "cipher_times_cipher":
                    result_ctxt = ciphertexts1[i] * ciphertexts2[i]
                
                result_ciphertexts.append(result_ctxt)
            operation_time = time.time() - start_time
            
            # Decryption time
            decryption_time = 0
            final_result = []
            
            start_time = time.time()
            for result_ctxt in result_ciphertexts:
                result_ptxt = HE.decryptPtxt(result_ctxt)
                result_arr = HE.decodeInt(result_ptxt)
                # Only take the actual data (remove padding from last chunk)
                final_result.extend(result_arr[:min(max_slots, vector_size - len(final_result))])
            decryption_time = time.time() - start_time
            
            # Verification
            if operation == "cipher_plus_cipher" or operation == "cipher_plus_plain":
                expected = (arr1 + arr2) % HE.t
            else:  # multiplication operations
                expected = (arr1 * arr2) % HE.t
            
            correct = np.array_equal(np.array(final_result), expected)
            
            # Log result
            result_row = {
                'poly_degree': poly_degree,
                'vector_size': vector_size,
                'operation': operation,
                'encryption_time': encryption_time,
                'operation_time': operation_time,
                'decryption_time': decryption_time,
                'total_time': encryption_time + operation_time + decryption_time,
                'correct': correct,
                'num_ciphertexts': num_ciphertexts,
                'data_type': 'same_number'
            }
            
            self.results.append(result_row)
            return True
            
        except Exception as e:
            print(f"    ERROR in {operation}: {e}")
            result_row = {
                'poly_degree': poly_degree,
                'vector_size': vector_size,
                'operation': operation,
                'encryption_time': None,
                'operation_time': None,
                'decryption_time': None,
                'total_time': None,
                'correct': False,
                'num_ciphertexts': math.ceil(vector_size / poly_degree),
                'data_type': 'same_number'
            }
            self.results.append(result_row)
            return False
    
    def run_experiment(self):
        """Run the complete experiment for same number in all slots"""
        poly_modulus_degrees = [4096, 8192, 16384, 32768]
        vector_sizes = [2**i for i in range(10, 21)]  # 1024 to 1048576
        operations = ["cipher_plus_cipher", "cipher_times_plain", 
                     "cipher_plus_plain", "cipher_times_cipher"]
        
        total_combinations = len(poly_modulus_degrees) * len(vector_sizes) * len(operations)
        current_combination = 0
        
        print(f"Starting Experiment: {self.experiment_name}")
        print(f"Testing SAME NUMBER in all slots")
        print(f"Total combinations to test: {total_combinations}")
        print("=" * 80)
        
        for poly_degree in poly_modulus_degrees:
            print(f"\nTesting with polynomial modulus degree: {poly_degree}")
            
            for vector_size in vector_sizes:
                num_ciphertexts_needed = math.ceil(vector_size / poly_degree)
                print(f"  Vector size: {vector_size} (requires {num_ciphertexts_needed} ciphertexts)")
                
                try:
                    # Generate context and test data
                    HE = self.generate_context(poly_degree)
                    arr1, arr2 = self.generate_same_number_data(vector_size)
                    
                    # Run all operations
                    for operation in operations:
                        current_combination += 1
                        print(f"    [{current_combination}/{total_combinations}] {operation}")
                        
                        self.run_operation_tests(
                            HE, arr1, arr2, vector_size, poly_degree, operation
                        )
                    
                    # Clean up
                    del HE
                    
                except Exception as e:
                    print(f"    ERROR in setup: {e}")
                    for operation in operations:
                        current_combination += 1
                        result_row = {
                            'poly_degree': poly_degree,
                            'vector_size': vector_size,
                            'operation': operation,
                            'encryption_time': None,
                            'operation_time': None,
                            'decryption_time': None,
                            'total_time': None,
                            'correct': False,
                            'num_ciphertexts': math.ceil(vector_size / poly_degree),
                            'data_type': 'same_number'
                        }
                        self.results.append(result_row)
                    continue
        
        # Save results to CSV
        self.save_results_to_csv()
        
    def save_results_to_csv(self):
        """Save experiment results to CSV file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.experiment_name}_{timestamp}.csv"
        
        os.makedirs("experiment_results", exist_ok=True)
        filepath = os.path.join("experiment_results", filename)
        
        fieldnames = [
            'poly_degree', 
            'vector_size', 
            'operation',
            'encryption_time', 
            'operation_time', 
            'decryption_time',
            'total_time',
            'correct',
            'num_ciphertexts',
            'data_type'
        ]
        
        with open(filepath, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in self.results:
                writer.writerow(result)
        
        print(f"\nResults saved to: {filepath}")
        
    def generate_summary(self):
        """Generate a summary of the experiment results"""
        if not self.results:
            print("No results to summarize")
            return
        
        successful_ops = [r for r in self.results if r.get('correct', False)]
        
        print(f"\n{'='*80}")
        print(f"EXPERIMENT SUMMARY - SAME NUMBER IN ALL SLOTS")
        print(f"{'='*80}")
        print(f"Total operations tested: {len(self.results)}")
        print(f"Successful operations: {len(successful_ops)}")
        print(f"Success rate: {len(successful_ops)/len(self.results)*100:.2f}%")

def main_same_number():
    """Main function to run the same number experiment"""
    experiment = SameNumberExperiment()
    
    start_time = time.time()
    experiment.run_experiment()
    total_time = time.time() - start_time
    
    experiment.generate_summary()
    
    print(f"\nTotal experiment time: {total_time:.2f} seconds")
    print("Same Number Experiment completed!")

if __name__ == "__main__":
    main_same_number()
