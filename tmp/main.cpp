#include <bits/stdc++.h>
#include "cxxopts.hpp"
using namespace std;

struct xgdc_values_t {
    int d;
    int x;
    int y;
};

bool containsWhiteSpaces(const string& str) {
    for (char c : str)
        if (isspace(c))
            return true;
    return false;
}

vector<string> split(const string& str, char separator) {
    vector<string> tokens;
    stringstream ss(str);
    string token;
    while (getline(ss, token, separator))
        if (!containsWhiteSpaces(token))
            tokens.push_back(token);
    return tokens;
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

unordered_set<int> primeFactors(int n) {
    unordered_set<int> factors;
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

bool validPQ(int p, int q) {
    auto factors1 = primeFactors(p);
    auto factors2 = primeFactors(q);
    int top = min(factors1.size(), factors2.size());
    auto it = factors1.begin();

    while (top--) {
        if (*it != 1 && factors2.count(*it))
            return false;
        it++;
    }
    return true;
}

int isSuperincreasing(vector<int> &seq) {
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

bool isInteger(string &str) {
    for (char c : str)
        if (!isdigit(c))
            return false;
    return true;
}

void generatePublicKey(int p, int q) {
    
}

int main() {
    string privateKeyFileName = "private_key.txt";
    ifstream t(privateKeyFileName);
    string str((istreambuf_iterator<char>(t)),
                istreambuf_iterator<char>());

    auto vals = split(str, ',');
    vector<int> values;

    for (string val : vals) {
        if (!isInteger(val)) {
            cout << "not a number\n";
            return 1;
        }
        values.push_back(atoi(val.c_str()));
    }
    int p = 7;
    int q = 32;

    if (!validPQ(p,q)) {
        cout << "p q invalid\n"; 
        return 1;
    }
    int sum = isSuperincreasing(values);
    if (sum == -1) {
        cout << "sum's wrong\n";
        return 1;
    }
    if (sum > q) {
        cout << "q is not big enough!\n";
        return 1;
    }
    
    vector<int> publicKey;
    for (int x : values)
        publicKey.push_back((p * x) % q);

    for (int x : publicKey)
        cout << x << " ";
    cout << "\n";

    int invertedP = getInvertedP(p, q);
    cout << invertedP << "\n";

    /* 
    
    std::ifstream file;
    if (arg["binary"].as<bool>())
        file = std::ifstream(fileName, std::ios::binary);
    else
        file = std::ifstream(fileName);
    if (file.fail())
        return 1;
    inputData = std::vector<uint8_t>(std::istreambuf_iterator<char>(file), {});
    file.close();
    DEBUG("OK\n");
    return 0;
    
    */
    return 0;
}