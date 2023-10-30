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


cpp_int IntegerToCppint(const Integer number) {
    ostringstream oss;
    oss << number;
    string str(oss.str());
    str.erase(str.size() - 1, 1);
    cpp_int res(str);
    return res;
}


cpp_int GenJorV(cpp_int m) {
    cpp_int res;
    do {
        res = Random(2, m - 1);
    } while (ExtendedEuclid(res, m)[0] != 1);
    return res;
}


void GuillouQuisquater(int l) {
    //Генерация p, q, n  
    cpp_int p, q, n;
    do {
        InvertibleRSAFunction params;
        params.GenerateRandomWithKeySize(rng, l);
        p = IntegerToCppint(params.GetPrime1());
        q = IntegerToCppint(params.GetPrime2());
        n = IntegerToCppint(params.GetModulus());
    } while (p == q);
    cout << "\nГенерация открытых данных:\n   число n = pq = " << p << " * " << q << " = " << n << "\n";

    //Генерация v
    cpp_int fiN = (p - 1) * (q - 1);
    cpp_int v = GenJorV(fiN);
    cout << "   число v = " << v << "\n";

    //Генерация J
    cpp_int J = GenJorV(n);
    cout << "   значение от открытых атрибутов Пегги: J = " << J << "\n";

    //Вычисление B
    cpp_int s = ModNegative(ExtendedEuclid(v, fiN)[1], fiN);
    cpp_int obrJ = ModNegative(ExtendedEuclid(J, n)[1], n);
    cpp_int B = Exponentiation(obrJ, s, n);
    cout << "\nПегги:\n   вычислила секрет B = J^(-s) (mod n) = " << B << "\n";

    //Выбор r и вычисление T
    cpp_int r = Random(1, n - 1);
    cout << "   выбрала r = " << r << "\n";
    cpp_int T = Exponentiation(r, v, n);
    cout << "   отправила Виктору T = r^v (mod n) = " << T << "\n";

    //Выбор d
    cpp_int d = Random(0, v - 1);
    cout << "\nВиктор:\n   отправил Пегги d = " << d << "\n";

    //Вычисление D
    cpp_int D = r * Exponentiation(B, d, n) % n;
    cout << "\nПегги:\n   отправила Виктору D = r * B^d (mod n) = " << D << "\n";

    //Вычисление T' и проверка T'=D^v J^d (mod n)
    cpp_int Tsh = Exponentiation(D, v, n) * Exponentiation(J, d, n) % n;
    cout << "\nВиктор:\n   вычислил T' = D^v * J^d (mod n) = " << Tsh << "\n";
    if (T == Tsh)
        cout << "\nРезультат:\n   T = T', значит Пегги знает секрет B\n";
    else
        cout << "\nРезультат:\n   T != T', значит Пегги не знает секрет B\n";
}


int main(int argc, char* argv[]) {
    setlocale(LC_ALL, "Russian");
    int l;
    if (argc == 1) {
        cerr << "Необходимо ввести l - битовую длину числа n\n";
        return 0;
    }
    try {
        l = stoi(argv[1]);
    }
    catch (std::invalid_argument) {
        cerr << "Число l должно быть целым\n";
        return 0;
    }
    if (l < 16) {
        cerr << "Число l должно быть больше 15\n";
        return 0;
    }
    cout << "Протокол идентификации Гиллу-Кискате\n";
    GuillouQuisquater(l);
    return 0;
}