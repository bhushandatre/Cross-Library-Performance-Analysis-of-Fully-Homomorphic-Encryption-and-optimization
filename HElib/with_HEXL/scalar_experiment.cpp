// scalar_experiment.cpp
#include <helib/helib.h>
#include <iostream>
#include <vector>
#include <chrono>
#include <fstream>
#include <sys/resource.h>

using namespace helib;

// Get current memory usage (in KB)
long getMemoryUsageKB()
{
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    return usage.ru_maxrss;
}

// Helper to measure encryption time
long measureEncrypt(const helib::PubKey& publicKey,
                    const helib::Ptxt<helib::BGV>& ptxt,
                    helib::Ctxt& ctxt)
{
    auto start = std::chrono::high_resolution_clock::now();
    publicKey.Encrypt(ctxt, ptxt);
    auto end = std::chrono::high_resolution_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
}

// Helper to measure decryption time
long measureDecrypt(const helib::SecKey& secretKey,
                    const helib::Ctxt& ctxt,
                    helib::Ptxt<helib::BGV>& out)
{
    auto start = std::chrono::high_resolution_clock::now();
    secretKey.Decrypt(out, ctxt);
    auto end = std::chrono::high_resolution_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
}

void runScalarExperiment(std::ofstream &csvFile,
                         long polyDegree,
                         long scalarValue)
{
    // Build BGV context
    Context context = ContextBuilder<BGV>()
                          .m(polyDegree)
                          .p(4999)
                          .r(1)
                          .bits(300)
                          .c(2)
                          .build();

    SecKey secretKey(context);
    secretKey.GenSecKey();
    addSome1DMatrices(secretKey);
    const PubKey &publicKey = secretKey;

    // Encode scalars
    Ptxt<BGV> ptxtA(context, std::vector<long>(1, scalarValue));
    Ptxt<BGV> ptxtB(context, std::vector<long>(1, scalarValue + 1));

    // Encryption
    Ctxt ctxtA(publicKey), ctxtB(publicKey);
    long encTimeA = measureEncrypt(publicKey, ptxtA, ctxtA);
    long encTimeB = measureEncrypt(publicKey, ptxtB, ctxtB);

    auto logResult = [&](const std::string &label,
                         auto start,
                         auto end,
                         const Ctxt* ctxtRes = nullptr)
    {
        auto duration =
            std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

        long decTime = 0;
        if (ctxtRes != nullptr) {
            Ptxt<BGV> tmp(context);
            decTime = measureDecrypt(secretKey, *ctxtRes, tmp);
        }

        long mem = getMemoryUsageKB();
        csvFile << polyDegree << ","
                << scalarValue << ","
                << label << ","
                << duration << ","
                << encTimeA << ","
                << encTimeB << ","
                << decTime << ","
                << mem << "\n";
    };

    // PT + PT (no encryption/decryption needed)
    {
        auto start = std::chrono::high_resolution_clock::now();
        auto res = ptxtA + ptxtB;
        auto end = std::chrono::high_resolution_clock::now();
        logResult("PT+PT Add", start, end, nullptr);
    }

    // PT * PT (no encryption/decryption needed)
    {
        auto start = std::chrono::high_resolution_clock::now();
        auto res = ptxtA * ptxtB;
        auto end = std::chrono::high_resolution_clock::now();
        logResult("PT*PT Mul", start, end, nullptr);
    }

    // CT + PT
    {
        auto start = std::chrono::high_resolution_clock::now();
        Ctxt res = ctxtA;
        res += ptxtB;
        auto end = std::chrono::high_resolution_clock::now();
        logResult("CT+PT Add", start, end, &res);
    }

    // CT * PT
    {
        auto start = std::chrono::high_resolution_clock::now();
        Ctxt res = ctxtA;
        res *= ptxtB;
        auto end = std::chrono::high_resolution_clock::now();
        logResult("CT*PT Mul", start, end, &res);
    }

    // CT + CT
    {
        auto start = std::chrono::high_resolution_clock::now();
        Ctxt res = ctxtA;
        res += ctxtB;
        auto end = std::chrono::high_resolution_clock::now();
        logResult("CT+CT Add", start, end, &res);
    }

    // CT * CT
    {
        auto start = std::chrono::high_resolution_clock::now();
        Ctxt res = ctxtA;
        res *= ctxtB;
        auto end = std::chrono::high_resolution_clock::now();
        logResult("CT*CT Mul", start, end, &res);
    }
}

int main()
{
    std::ofstream csvFile("scalar_experiment_log.csv");
    csvFile << "PolyDegree,ScalarValue,Operation,OpTime(us),EncTimeA(us),EncTimeB(us),DecTime(us),Memory(KB)\n";

    std::vector<long> polyDegrees = {128 , 256 , 512 , 1024, 2048, 4096, 8192, 16384, 32768};
    std::vector<long> scalarValues = {1, 10, 100, 1000, 10000, 100000};

    for (auto pd : polyDegrees)
    {
        for (auto sv : scalarValues)
        {
            runScalarExperiment(csvFile, pd, sv);
        }
    }

    csvFile.close();
    std::cout << "✅ Scalar experiments completed. Results saved in scalar_experiment_log.csv\n";
    return 0;
}

