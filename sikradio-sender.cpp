#include <boost/program_options.hpp>
#include <iostream>

using namespace std;
namespace po = boost::program_options;

int main(int argc, char *argv[]) {
    try {
        po::options_description desc("Program options");
        desc.add_options()
            ("a,a", po::value<string>()->required(), "address")
            ("P,P", po::value<uint32_t>()->default_value(28422), "port")
            ("p,p", po::value<uint32_t>()->default_value(512), "PSIZE")
            ("n,n", po::value<string>()->default_value("Nienazwany nadajnik"), "name");

        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);

        cout << "a: " << vm["a"].as<string>() << endl;
        cout << "P: " << vm["P"].as<uint32_t>() << endl;
        cout << "p: " << vm["p"].as<uint32_t>() << endl;
        cout << "n: " << vm["n"].as<string>() << endl;
    } catch (exception &e) {
        cerr << "error: " << e.what() << endl;
        return 1;
    }

    return 0;
}
