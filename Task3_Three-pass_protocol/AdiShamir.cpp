#include <iostream>
#include <string>
#include "rsa.h"
#include "osrng.h"
#include <random>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random/uniform_int.hpp>
#include <boost/random/variate_generator.hpp>


using namespace std;
using namespace CryptoPP;
using namespace boost::multiprecision;
using namespace boost::random;


AutoSeededRandomPool rng;


cpp_int ModNegative(cpp_int a, cpp_int p) {
    while (a < 0)
        a = a + p;
    return a % p;
}


vector <cpp_int> ExtendedEuclid(cpp_int a, cpp_int b) {
    vector <cpp_int> res(3);
    if (a == 0) {
        res = { b, 0, 1 };
        return res;
    }
    vector <cpp_int> c = ExtendedEuclid(b % a, a);
    res = { c[0], c[2] - (b / a) * c[1], c[1] };
    return res;
}


cpp_int Exponentiation(cpp_int x, cpp_int n, cpp_int m) {
    cpp_int N = n, Y = 1, Z = x % m;
    while (N != 0) {
        cpp_int lastN = N % 2;
        N = N / 2;
        if (lastN == 0) {
            Z = (Z * Z) % m;
            continue;
        }
        Y = (Y * Z) % m;
        if (N == 0)
            break;
        Z = (Z * Z) % m;
    }
    return Y % m;
}


cpp_int Random(cpp_int minim, cpp_int maxim) {
    random_device gen;
    boost::random::uniform_int_distribution<cpp_int> ui(minim, maxim);
    return ui(gen);
}


pair <cpp_int, cpp_int> GenKey(cpp_int p) {
    cpp_int publicKey = Random(2, p - 2);
    while (ExtendedEuclid(publicKey, p - 1)[0] != 1)
        publicKey = Random(2, p - 2);
    cpp_int privateKey = ModNegative(ExtendedEuclid(publicKey, p - 1)[1], p - 1);
    return make_pair(publicKey, privateKey);
}


void AdiShamir(int l) {
    //Генерация p  
    InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, l*2);
    const Integer& pstr = params.GetPrime1();
    ostringstream oss;
    oss << pstr;
    string s(oss.str());
    s.erase(s.size() - 1, 1);
    cpp_int p(s);
    cout << "\nБыло сгенерировано простое число p = " << p << "\n";

    //Генерация ключей для шифрования и расшифрования
    pair<cpp_int, cpp_int> keys = GenKey(p);
    cpp_int EA = keys.first;
    cpp_int DA = keys.second;
    keys = GenKey(p);
    cpp_int EB = keys.first;
    cpp_int DB = keys.second;
    cout << "Были получены следующие личные ключи:\n";
    cout << "   (EA, DA) = (" << EA << ", " << DA << ")\n";
    cout << "   (EB, DB) = (" << EB << ", " << DB << ")\n";

    // Генерация секретного ключа
    cpp_int K = Random(2, p - 1);
    cout << "Был сгенерирован секретный ключ K = " << K << "\n";

    //1
    cout << "\nАлиса шифрует K своим ключом EA и отправляет результат Бобу:\n";
    cpp_int C1 = Exponentiation(K, EA, p);
    cout << "C1 = EA(K) = " << C1 << "\n";

    //2
    cout << "\nБоб шифрует С1 своим ключом EB и отправляет результат Алисе:\n";
    cpp_int C2 = Exponentiation(C1, EB, p);
    cout << "C2 = EB(C1) = " << C2 << "\n";

    //3
    cout << "\nАлиса расшифровывает C2 своим ключом DA и отправляет результат Бобу:\n";
    cpp_int C3 = Exponentiation(C2, DA, p);
    cout << "C3 = DA(C2) = " << C3 << "\n";

    //4
    cout << "\nБоб расшифровывает С3 своим ключом DB, получая секретный ключ:\n";
    cpp_int res = Exponentiation(C3, DB, p);
    cout << "K = " << res << "\n";

    //Проверка
    if (res != K)
        cout << "\nБоб получил неверное сообщение\n";
    else
        cout << "\nКлюч, который отправляла Алиса и который получил Боб совпал\n";
}


int main(int argc, char* argv[]) {
    setlocale(LC_ALL, "Russian");
    int l;
    if (argc == 1) {
        cerr << "Необходимо ввести l - битовую длину простого числа p\n";
        return 0;
    }
    try {
        l = stoi(argv[1]);
    }
    catch (std::invalid_argument) {
        cerr << "Число l должно быть целым\n";
        return 0;
    }
    if (l < 8) {
        cerr << "Число l должно быть больше 7\n";
        return 0;
    }
    cout << "Трёхпроходный протокол Шамира\n";
    AdiShamir(l);
    return 0;
}