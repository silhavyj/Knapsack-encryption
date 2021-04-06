#include <iostream>
#include <unordered_map>
#include <vector>
#include <fstream>
#include <cmath>
#include <bitset>

#include "cxxopts.hpp"

#define KEY_FILE_SEPARATOR ','
#define DEBUG(msg) (arg["verbose"].as<bool>() && std::cout << msg << std::flush)

cxxopts::ParseResult arg;
cxxopts::Options options("./knapsack <input> <p> <q>", "KIV/BIT task 4 - knapsack encryption/decryption");

std::vector<uint8_t> inputData;
std::vector<int> privateKey;
std::vector<int> publicKey;
std::vector<int> encryptedData;
std::vector<int> decryptedData;

struct xgdc_values_t {
    int d;
    int x;
    int y;
};

int readInputFile(std::string inputFileName) {
    DEBUG("loading the content of the input file...");
    std::ifstream file(inputFileName, std::ios::binary);
    if (file.fail())
        return 1;
    inputData = std::vector<uint8_t>(std::istreambuf_iterator<char>(file), {});
    file.close();
    DEBUG("OK\n");
    return 0;
}

bool isInteger(std::string &str) {
    for (char c : str)
        if (!isdigit(c))
            return false;
    return true;
}

std::unordered_set<int> primeFactors(int n) {
    std::unordered_set<int> factors;
    while ((n & 1) == 0) {
        factors.insert(2);
        n >>= 1;
    }
    for (int i = 3; i <= sqrt(n); i += 2) 
        while (n % i == 0) {
            factors.insert(i);
            n /= i;
        }
    if (n > 2)
        factors.insert(n);
    return factors;
}

bool relativelyPrime(int p, int q) {
    auto factors1 = primeFactors(p);
    auto factors2 = primeFactors(q);
    int top = std::min(factors1.size(), factors2.size());
    auto it = factors1.begin();

    while (top--) {
        if (*it != 1 && factors2.count(*it))
            return false;
        it++;
    }
    return true;
}

std::string strip(const std::string &str) {
    auto start_it = str.begin();
    auto end_it = str.rbegin();

    while (std::isspace(*start_it))
        ++start_it;
    while (std::isspace(*end_it))
        ++end_it;
    return std::string(start_it, end_it.base());
}

std::vector<std::string> split(std::string& str, char separator) {
    str = strip(str);
    std::vector<std::string> tokens;
    std::stringstream ss(str);
    std::string token;
    while (getline(ss, token, separator)) {
        if (token.length() > 0 && std::isspace(token[0]))
            token = strip(token);
        if (token != "")
            tokens.push_back(token);
    }
    return tokens;
}

int readPrivateKey(std::string fileName) {
    DEBUG("reading the private key from '");
    DEBUG(fileName);
    DEBUG("'...");

    std::ifstream file(fileName);
    if (file.fail())
        return 1;
    std::string str((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    auto tokens = split(str, KEY_FILE_SEPARATOR);
    for (auto token : tokens) {
        if (!isInteger(token))
            return 2;
        privateKey.push_back(atoi(token.c_str()));
    }
    DEBUG("OK\n");
    return 0;
}

int isSuperincreasing(std::vector<int> &seq) {
    int sum = 0;
    for (int i = 0; i < (int)seq.size(); i++) {
        if (i == 0) {
            sum += seq[i];
            continue;
        } else {
            if (seq[i] < seq[i-1] || seq[i] < sum)
                return -1;
            sum += seq[i];
        }
    }
    return sum;
}

void generatePublicKey(int p, int q) {
    DEBUG("generating a public key...");
    std::ofstream file(arg["public-key"].as<std::string>());
    for (int x : privateKey) {
        publicKey.push_back((p * x) % q);
        file << *publicKey.rbegin() << ",";
    }
    file.close();
    DEBUG("OK\n");
}

int getBit(int index) {
    int p = index / 8;
    int b = index % 8;
    if (p >= (int)inputData.size())
        return -1;
    return (inputData[p] >> (7 - b)) & 1;
}

void encryptData() {
    DEBUG("starting encrypting the input data\n");
    int blockSum = 0;
    int value;
    int i = 0;

    while (1) {
        value = getBit(i);
        if (value == -1) {
            encryptedData.push_back(blockSum);
            break;
        }
        DEBUG(value);
        if (value == 1)
            blockSum += publicKey[i % publicKey.size()];
        if ((i+1) % publicKey.size() == 0) {
            DEBUG(" | ");
            DEBUG(blockSum);
            DEBUG("\n");
            encryptedData.push_back(blockSum);
            blockSum = 0;
        }
        i++;
    }
    if (arg["print"].as<bool>()) {
        std::cout << "encrypted data: ";
        for (int x : encryptedData)
            std::cout << x << " ";
        std::cout << "\n";
    }
}

xgdc_values_t xgdc(int a, int b) {
    if (b == 0)
        return {a, 1, 0};
    else {
        auto vals = xgdc(b, a % b);
        return {vals.d, vals.y, vals.x - vals.y * (a / b)};
    }
}

int getInvertedP(int p, int q) {
    auto values = xgdc(p, q);
    if (values.x >= 0)
        return values.x;
    return q + values.x;
}

std::vector<int> findValuesInPrivateKey(int n) {
    std::vector<int> bin(privateKey.size(), 0);
    for (int i = privateKey.size() - 1; i >= 0; i--)
        if (privateKey[i] <= n) {
            n -= privateKey[i];
            bin[i] = 1;
            if (n == 0)
                return bin;
        }
    return bin; 
}

void decryptData(int p, int q) {
    DEBUG("starting decrypting the input data\n");
    DEBUG("calculating p^(-1) using the extended euclidean algorithm...");
    int invertedP = getInvertedP(p, q);
    DEBUG("OK (");
    DEBUG("p=");
    DEBUG(invertedP);
    DEBUG(")\n");

    std::string originalData = "";
    for (int x : encryptedData) {
        int val = (invertedP * x) % q;
        if (arg["verbose"].as<bool>())
            std::cout << "(" << invertedP << " * " << x << ") % " << q << " = " << val << " | ";

        auto bin = findValuesInPrivateKey(val);
        for (int b : bin) {
            originalData += std::to_string(b);
            DEBUG(b);
        }
        DEBUG("\n");
    }
    uint8_t block = 0;
    int pos = 7;
    for (int i = 0; i < (int)originalData.length(); i++) {
        block |= (originalData[i] == '1') << pos;
        if (pos == 0) {
            decryptedData.push_back(block);
            std::cout << (char)block;
            pos = 7;
            block = 0;
        } else {
            pos--;
        }
    }
}

int main(int argc, char *argv[]) {
    options.add_options()
        ("v,verbose", "print out info as the program proceeds", cxxopts::value<bool>()->default_value("false"))
        ("o,output", "name of the output file", cxxopts::value<std::string>()->default_value("output.txt"))
        ("k,private-key", "file containing the private key", cxxopts::value<std::string>()->default_value("private_key.txt"))
        ("l,public-key", "file containing the private key", cxxopts::value<std::string>()->default_value("public_key.txt"))
        ("p,print", "print out the binary data as well as the decrypted text", cxxopts::value<bool>()->default_value("false"))
        ("h,help", "print help")
    ;
    arg = options.parse(argc, argv);
    if (arg.count("help")) {
        std::cout << options.help() << std::endl;
        return 0;
    }
    if (argc < 4) {
        std::cout << "ERR: Compulsory parameters are not specified!\n";
        std::cout << "     Run './knapsack --help'\n";
        return 1;
    }    
    std::string inputFileName = argv[1];
    std::string pStr = argv[2];
    std::string qStr = argv[3];

    if (readInputFile(inputFileName) != 0) {
        std::cout << "input file not found!\n";
        return 1;
    }
    DEBUG("parsing values p and q...");
    if (!isInteger(pStr)) {
        std::cout << "parameter '" << pStr << "' is invalid!\n";
        return 1;
    }
    if (!isInteger(qStr)) {
        std::cout << "parameter '" << qStr << "' is invalid!\n";
        return 1;
    }
    DEBUG("OK\n");

    DEBUG("checking if p and q are relative prime...");
    int p = atoi(pStr.c_str());
    int q = atoi(qStr.c_str());
    if (relativelyPrime(p, q) == false) {
        std::cout << "values p and q are not relatively prime!\n";
        return 1;
    }
    DEBUG("OK\n");

    int ret = readPrivateKey(arg["private-key"].as<std::string>());
    if (ret == 1)
        std::cout << "'" << arg["private-key"].as<std::string>() << "' doesn't exist!\n";
    else if (ret == 2)
        std::cout << "the private key file contains values that are not numbers!\n";
    if (ret != 0)
        return 1;
    
    DEBUG("making sure the private key is a super-increasing sequence and that q is greater than the sum of all the values of the private key...");
    int sum = isSuperincreasing(privateKey);
    if (sum == -1) {
        std::cout << "the private key is not a super-increasing sequence!\n";
        return 1;
    }
    if (q <= sum) {
        std::cout << "the sum of all the values (" << sum << ") is greater than q (" << q << ")!\n";
        return 1;
    }
    DEBUG("OK\n");

    generatePublicKey(p, q);
    encryptData();
    decryptData(p, q);
    return 0;
}