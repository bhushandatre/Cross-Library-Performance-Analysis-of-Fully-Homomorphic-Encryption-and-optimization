import Pyfhel
import numpy as np
import time
import csv
from datetime import datetime
import os

class RotationExperiment:
    def __init__(self):
        self.results = []
        self.experiment_name = "Rotation_Experiment"
        
    def generate_context(self, poly_modulus_degree):
        """Generate HE context with given polynomial modulus degree"""
        HE = Pyfhel.Pyfhel()
        
        # For BFV scheme with batching
        if poly_modulus_degree == 1024:
            t = 65537
        elif poly_modulus_degree == 4096:
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
        
        # Generate rotation keys - needed for rotation operations
        HE.rotateKeyGen()
        
        return HE
    
    def generate_test_data(self, vector_size):
        """Generate test data with sequential numbers"""
        arr = np.array([i for i in range(vector_size)], dtype=np.int64)
        print(f"    Generated vector of size: {vector_size}")
        return arr
    
    def test_left_rotation(self, HE, arr, vector_size, poly_degree):
        """Test left rotation by 1 position"""
        try:
            # Pad array to fill all slots if needed
            if len(arr) < poly_degree:
                arr_padded = np.pad(arr, (0, poly_degree - len(arr)), mode='constant')
            else:
                arr_padded = arr
            
            # Encode and encrypt
            ptxt = HE.encodeInt(arr_padded)
            ctxt = HE.encryptPtxt(ptxt)
            
            # Perform left rotation
            start_time = time.time()
            rotated_ctxt = HE.rotate(ctxt, -1)  # Negative for left rotation
            rotation_time_ms = (time.time() - start_time) * 1000
            
            result_row = {
                'poly_degree': poly_degree,
                'vector_size': vector_size,
                'rotation_type': 'left_rotation',
                'rotation_time_ms': rotation_time_ms
            }
            
            self.results.append(result_row)
            return True
            
        except Exception as e:
            print(f"    ERROR in left rotation: {e}")
            result_row = {
                'poly_degree': poly_degree,
                'vector_size': vector_size,
                'rotation_type': 'left_rotation',
                'rotation_time_ms': None
            }
            self.results.append(result_row)
            return False
    
    def test_right_rotation(self, HE, arr, vector_size, poly_degree):
        """Test right rotation by 1 position"""
        try:
            # Pad array to fill all slots if needed
            if len(arr) < poly_degree:
                arr_padded = np.pad(arr, (0, poly_degree - len(arr)), mode='constant')
            else:
                arr_padded = arr
            
            # Encode and encrypt
            ptxt = HE.encodeInt(arr_padded)
            ctxt = HE.encryptPtxt(ptxt)
            
            # Perform right rotation
            start_time = time.time()
            rotated_ctxt = HE.rotate(ctxt, 1)  # Positive for right rotation
            rotation_time_ms = (time.time() - start_time) * 1000
            
            result_row = {
                'poly_degree': poly_degree,
                'vector_size': vector_size,
                'rotation_type': 'right_rotation',
                'rotation_time_ms': rotation_time_ms
            }
            
            self.results.append(result_row)
            return True
            
        except Exception as e:
            print(f"    ERROR in right rotation: {e}")
            result_row = {
                'poly_degree': poly_degree,
                'vector_size': vector_size,
                'rotation_type': 'right_rotation',
                'rotation_time_ms': None
            }
            self.results.append(result_row)
            return False
    
    def test_columns_rotation(self, HE, arr, vector_size, poly_degree):
        """Test column rotation (special rotation for matrix operations)"""
        try:
            # For column rotation, we rotate by the square root of vector size
            # This simulates rotating columns in a matrix
            rotation_step = int(np.sqrt(vector_size))
            
            # Pad array to fill all slots if needed
            if len(arr) < poly_degree:
                arr_padded = np.pad(arr, (0, poly_degree - len(arr)), mode='constant')
            else:
                arr_padded = arr
            
            # Encode and encrypt
            ptxt = HE.encodeInt(arr_padded)
            ctxt = HE.encryptPtxt(ptxt)
            
            # Perform column rotation
            start_time = time.time()
            rotated_ctxt = HE.rotate(ctxt, rotation_step)
            rotation_time_ms = (time.time() - start_time) * 1000
            
            result_row = {
                'poly_degree': poly_degree,
                'vector_size': vector_size,
                'rotation_type': 'columns_rotation',
                'rotation_time_ms': rotation_time_ms
            }
            
            self.results.append(result_row)
            return True
            
        except Exception as e:
            print(f"    ERROR in columns rotation: {e}")
            result_row = {
                'poly_degree': poly_degree,
                'vector_size': vector_size,
                'rotation_type': 'columns_rotation',
                'rotation_time_ms': None
            }
            self.results.append(result_row)
            return False
    
    def run_experiment(self):
        """Run the complete rotation experiment"""
        poly_modulus_degrees = [1024, 4096, 8192, 16384, 32768]
        vector_sizes = [2**i for i in range(4, 11)]  # 16 to 1024
        
        total_combinations = len(poly_modulus_degrees) * len(vector_sizes) * 3  # 3 rotation types
        current_combination = 0
        
        print(f"Starting Experiment: {self.experiment_name}")
        print(f"Testing ROTATION OPERATIONS")
        print(f"Polynomial degrees: {poly_modulus_degrees}")
        print(f"Vector sizes: {vector_sizes}")
        print(f"Rotation types: left_rotation, right_rotation, columns_rotation")
        print(f"Total combinations to test: {total_combinations}")
        print("NOTE: All times are logged in MILLISECONDS")
        print("=" * 80)
        
        for poly_degree in poly_modulus_degrees:
            print(f"\nTesting with polynomial modulus degree: {poly_degree}")
            
            for vector_size in vector_sizes:
                print(f"  Vector size: {vector_size}")
                
                try:
                    # Skip if vector size exceeds poly_degree
                    if vector_size > poly_degree:
                        print(f"    Skipping - vector size {vector_size} exceeds poly_degree {poly_degree}")
                        for rotation_type in ['left_rotation', 'right_rotation', 'columns_rotation']:
                            current_combination += 1
                            result_row = {
                                'poly_degree': poly_degree,
                                'vector_size': vector_size,
                                'rotation_type': rotation_type,
                                'rotation_time_ms': None
                            }
                            self.results.append(result_row)
                        continue
                    
                    # Generate context and test data
                    HE = self.generate_context(poly_degree)
                    arr = self.generate_test_data(vector_size)
                    
                    # Test left rotation
                    current_combination += 1
                    print(f"    [{current_combination}/{total_combinations}] Testing left rotation")
                    self.test_left_rotation(HE, arr, vector_size, poly_degree)
                    
                    # Test right rotation
                    current_combination += 1
                    print(f"    [{current_combination}/{total_combinations}] Testing right rotation")
                    self.test_right_rotation(HE, arr, vector_size, poly_degree)
                    
                    # Test columns rotation
                    current_combination += 1
                    print(f"    [{current_combination}/{total_combinations}] Testing columns rotation")
                    self.test_columns_rotation(HE, arr, vector_size, poly_degree)
                    
                    # Clean up
                    del HE
                    
                except Exception as e:
                    print(f"    ERROR in setup: {e}")
                    # Log failed operations for this combination
                    for rotation_type in ['left_rotation', 'right_rotation', 'columns_rotation']:
                        current_combination += 1
                        result_row = {
                            'poly_degree': poly_degree,
                            'vector_size': vector_size,
                            'rotation_type': rotation_type,
                            'rotation_time_ms': None
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
            'rotation_type',
            'rotation_time_ms'
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
        
        successful_ops = [r for r in self.results if r.get('rotation_time_ms') is not None]
        
        print(f"\n{'='*80}")
        print(f"EXPERIMENT SUMMARY - ROTATION OPERATIONS")
        print(f"{'='*80}")
        print(f"Total rotation operations tested: {len(self.results)}")
        print(f"Successful operations: {len(successful_ops)}")
        
        if successful_ops:
            # Calculate average rotation times by type
            rotation_types = set(r['rotation_type'] for r in successful_ops)
            print(f"\nAverage rotation times by type:")
            for rotation_type in rotation_types:
                type_ops = [r for r in successful_ops if r['rotation_type'] == rotation_type]
                avg_time = np.mean([r['rotation_time_ms'] for r in type_ops])
                print(f"  {rotation_type:15}: {avg_time:.3f} ms")
            
            # Calculate average rotation times by polynomial degree
            print(f"\nAverage rotation times by polynomial degree:")
            for poly_degree in [1024, 4096, 8192, 16384, 32768]:
                poly_ops = [r for r in successful_ops if r['poly_degree'] == poly_degree]
                if poly_ops:
                    avg_time = np.mean([r['rotation_time_ms'] for r in poly_ops])
                    print(f"  PolyDeg {poly_degree:5}: {avg_time:.3f} ms")

def main_rotation_experiment():
    """Main function to run the rotation experiment"""
    experiment = RotationExperiment()
    
    start_time = time.time()
    experiment.run_experiment()
    total_time = time.time() - start_time
    
    experiment.generate_summary()
    
    print(f"\nTotal experiment time: {total_time:.2f} seconds")
    print("Rotation Experiment completed!")

if __name__ == "__main__":
    main_rotation_experiment()
