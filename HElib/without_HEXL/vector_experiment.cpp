#include <helib/helib.h>
#include <iostream>
#include <fstream>
#include <chrono>
#include <sys/resource.h>
#include <vector>

// Memory usage
long getMemoryUsageKB()
{
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    return usage.ru_maxrss;
}

// Timer helper
class Timer {
public:
    std::chrono::high_resolution_clock::time_point start;
    void tic() { start = std::chrono::high_resolution_clock::now(); }
    double toc() {
        auto end = std::chrono::high_resolution_clock::now();
        return std::chrono::duration<double, std::milli>(end - start).count();
    }
};

// Log results
void logResult(std::ofstream& csv,
               int poly_degree,
               long vec_size,
               const std::string& experiment,
               const std::string& op,
               const std::string& combo,
               double enc_time,
               double dec_time,
               double op_time,
               long mem_kb)
{
    csv << poly_degree << ","
        << vec_size << ","
        << experiment << ","
        << op << ","
        << combo << ","
        << enc_time << ","
        << dec_time << ","
        << op_time << ","
        << mem_kb << "\n";
}

int main()
{
    std::ofstream csv("vector_results.csv");
    csv << "poly_degree,vec_size,experiment,operation,combination,enc_time_ms,dec_time_ms,op_time_ms,memory_kb\n";

    // Polynomial degrees to test
    std::vector<int> poly_degrees = {128 , 256 , 512 , 1024, 2048 , 4096 , 8192 , 16384 , 32768};
    // Vector sizes to test
    std::vector<long> vec_sizes = {1000, 10000 , 100000, 1000000};

    Timer timer;

    for (int m : poly_degrees) {
        std::cout << "Running experiments with polynomial degree m=" << m << "\n";

        // Build context
        auto context = helib::ContextBuilder<helib::BGV>()
                           .m(m)
                           .p(4999)
                           .r(1)
                           .bits(300)
                           .c(2)
                           .build();

        helib::SecKey secretKey(context);
        secretKey.GenSecKey();
        helib::addSome1DMatrices(secretKey);
        const helib::PubKey& publicKey = secretKey;
        const helib::EncryptedArray& ea = context.getEA();
        long nslots = ea.size();

        for (long N : vec_sizes) {
            std::cout << "  Vector size = " << N << "\n";

            long slots = std::min(N, nslots); // fill available slots
            std::vector<long> v1(slots, 3);
            std::vector<long> v2(slots, 9);

            helib::Ptxt<helib::BGV> p1(context, v1);
            helib::Ptxt<helib::BGV> p2(context, v2);

            helib::Ctxt c1(publicKey), c2(publicKey);

            // Encryption timing
            timer.tic();
            publicKey.Encrypt(c1, p1);
            double enc_time1 = timer.toc();

            timer.tic();
            publicKey.Encrypt(c2, p2);
            double enc_time2 = timer.toc();

            // Decryption timing
            helib::Ptxt<helib::BGV> dcheck(context);
            timer.tic();
            secretKey.Decrypt(dcheck, c1);
            double dec_time1 = timer.toc();

            timer.tic();
            secretKey.Decrypt(dcheck, c2);
            double dec_time2 = timer.toc();

            // PT+PT
            timer.tic();
            auto p_add = p1; p_add += p2;
            logResult(csv, m, N, "vector", "add", "pt+pt",
                      0, 0, timer.toc(), getMemoryUsageKB());

            timer.tic();
            auto p_mul = p1; p_mul *= p2;
            logResult(csv, m, N, "vector", "mul", "pt*pt",
                      0, 0, timer.toc(), getMemoryUsageKB());

            // CT+CT
            timer.tic();
            auto c_add = c1; c_add += c2;
            logResult(csv, m, N, "vector", "add", "ct+ct",
                      enc_time1 + enc_time2, dec_time1 + dec_time2,
                      timer.toc(), getMemoryUsageKB());

            timer.tic();
            auto c_mul = c1; c_mul *= c2;
            logResult(csv, m, N, "vector", "mul", "ct*ct",
                      enc_time1 + enc_time2, dec_time1 + dec_time2,
                      timer.toc(), getMemoryUsageKB());

            // PT+CT
            timer.tic();
            auto c_add2 = c1; c_add2 += p2;
            logResult(csv, m, N, "vector", "add", "pt+ct",
                      enc_time1, dec_time1, timer.toc(), getMemoryUsageKB());

            timer.tic();
            auto c_mul2 = c1; c_mul2 *= p2;
            logResult(csv, m, N, "vector", "mul", "pt*ct",
                      enc_time1, dec_time1, timer.toc(), getMemoryUsageKB());
        }
    }

    std::cout << "✅ Vector experiments complete. Results saved in vector_results.csv\n";
    return 0;
}

