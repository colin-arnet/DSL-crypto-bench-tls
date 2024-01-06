#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sys/stat.h>

using std::string;
using std::cout;
using std::endl;
using std::vector;

class Benchmark_Result{
    public:
        string name;
        int runs;
        vector<double> time;
        vector<double> throughput; // GB/s
        int num_msg;
        int msg_size;
        string data_path;
        Benchmark_Result(){
            this->name = "default";
            this->runs = 0;
            this->num_msg = 0;
            this->msg_size = 0;
            this->data_path = "$HOME/"; 
        }
        Benchmark_Result(string name, int runs, vector<double> time, vector<double> throughput, int num_msg, int msg_size, string data_path){
            this->name = name;
            this->runs = runs;
            this->time = time;
            this->throughput = throughput;
            this->num_msg = num_msg;
            this->msg_size = msg_size;
            this->data_path = data_path;
        }
        double vector_average(vector<double> input){
            double result = 0;
            for(int i = 0; i < input.size(); i++){
                result += input[i];
            }
            return result / input.size();
        }
        void print(){
            cout << "++++++++++" << endl;
            cout << "name: " << name << endl;
            cout << "runs: " << runs << endl;
            cout << "time: " << vector_average(this->time) << " microseconds" << endl;
            cout << "throughput: " << vector_average(this->throughput) << " GB/s" << endl;
            cout << "number of messages: " << num_msg << endl;
            cout << "message size: " << msg_size << " bytes" << endl;
            cout << "++++++++++" << endl;
        }
        void store_data(){
            string filename = data_path + name + "_" + std::to_string(num_msg) + "_" + std::to_string(msg_size) + ".csv";
            cout << "store data into file " << filename << endl;
            std::ofstream file;
            file.open(filename);
            file << "run, time in microseconds, throughput (GB/s)\n";
            for (int i = 0; i < runs; i++){
                string row = std::to_string(i) + ", " + std::to_string(time[i]) + ", " + std::to_string(throughput[i]) + "\n";
                file << row;
            }
            file.close();            
            return;
        }
};

class Benchmark_Config{
    public:
        // selected benchmarks
        int runs; // number of runs
        int num_msg; // number of messages
        int msg_size; // in bytes
        int key_length; // key size in bits 128, 192, 256
        int rsa_key_length; // rsa key size in bits 1024, 2048, 4096
        string data_path;
        Benchmark_Config(){
            this->runs = 10;
            this->num_msg = 1000;
            this->msg_size = 4096;
            this->key_length = 128;
            this->rsa_key_length = 4096;
            this->data_path = "$HOME/";
        }
        Benchmark_Config(int runs, int num_msg, int msg_size, int key_length, int rsa_key_length, string data_path){
            this->runs = runs;
            this->num_msg = num_msg;
            this->msg_size = msg_size;
            if (key_length == 128 || key_length == 192 || key_length == 256){
                this->key_length = key_length;
            } else {
                cout << "invalid key length set to default 256" << endl;
                this->key_length = 256;
            }
            if (rsa_key_length == 1024 || rsa_key_length == 2048 || rsa_key_length == 4096){
                this->rsa_key_length = rsa_key_length;
            } else{
                cout << "invalid rsa key length set to default 2048" << endl;
                this->rsa_key_length = 2048;
            }
            struct stat sb;
            if (stat(data_path.c_str(), &sb) == 0){
                cout << "the path is valid" << endl;
                this->data_path = data_path;
            } else {
                cout << "the path is invalid and is set to $HOME" << endl;
                this->data_path = "$HOME/";
            }
            
        }
};

void software_benchmark(Benchmark_Config config);

