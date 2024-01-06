#include <iostream>
#include <cstdlib>
#include <algorithm>
#include <vector>

#include "software_benchmark/software_benchmark.hpp"

using std::string;
using std::cout;
using std::endl;
using std::vector;

// Same ArgParser as in the Vitis Security Library Benchmarks
class ArgParser {
   public:
    ArgParser(int& argc, const char** argv) {
        for (int i = 1; i < argc; ++i) mTokens.push_back(string(argv[i]));
    }
    bool getCmdOption(const string option, string& value) const {
        vector<string>::const_iterator itr;
        itr = std::find(this->mTokens.begin(), this->mTokens.end(), option);
        if (itr != this->mTokens.end() && ++itr != this->mTokens.end()) {
            value = *itr;
            return true;
        }
        return false;
    }

   private:
    vector<string> mTokens;
};


int main(int argc, char* argv[]) {
    // key lengths 128, 192, 256 bits
    ArgParser parser(argc, (const char**) argv);
    string msg_size_str;
    int msg_size;
    if (!parser.getCmdOption("-len", msg_size_str)) {
        cout << "ERROR:msg length is not set!" << endl;
        return 1;
    } else {
        msg_size = std::stoi(msg_size_str);
        if (msg_size % 16 != 0) {
            cout << "ERROR: msg length is not multiple of 16!" << endl;
            return 1;
        }
        cout << "Length of single message is " << msg_size << " Bytes " << endl;
    }
    string msg_num_str;
    int msg_num;
    if (!parser.getCmdOption("-num", msg_num_str)) {
        cout << "ERROR: msg number is not set" << endl;
        return 1;
    } else {
        msg_num = std::stoi(msg_num_str);
        cout << "Message num is " << msg_num << endl;
    }
    string runs_str;
    int runs;
    if (!parser.getCmdOption("-runs", runs_str)){
        cout << "ERROR: number of runs is not set" << endl;
        return 1;
    } else {
        runs = std::stoi(runs_str);
        cout << "Number of runs is " << runs << endl;
    }

    string data_path;
    if(!parser.getCmdOption("-data_path", data_path)){
        cout << "ERROR: no path to store data" << endl;
        return 1;
    }

    Benchmark_Config config(runs, msg_num, msg_size, 0, 0, data_path);
    software_benchmark(config);
    return 0;
}