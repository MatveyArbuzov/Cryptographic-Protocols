#include <iostream>
#include <string>
#include "osrng.h"
#include "dh.h"
#include <random>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random/uniform_int.hpp>
#include <boost/random/variate_generator.hpp>


using namespace CryptoPP;
using namespace std;
using namespace boost::multiprecision;
using namespace boost::random;


AutoSeededRandomPool rnd;


cpp_int ModNegative(cpp_int a, cpp_int p) {
    if (a < 0) 
        a = a + p * (((-1 * a) / p) + 1);
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


void Elgamal(int l) {
    DH dh;
    cpp_int p, g, x, y, M, k, a, kobr, b, left, right;
    cout << "\nГенерация необходимых значений:\n";
	dh.AccessGroupParameters().GenerateRandomWithKeySize(rnd, l);
	p = IntegerToCppint(dh.GetGroupParameters().GetModulus());
    g = IntegerToCppint(dh.GetGroupParameters().GetGenerator());
    x = Random(2, p - 2);
    y = Exponentiation(g, x, p);
    M = Random(2, p - 2);
    cout << "   Cгенерировано простое число p = " << p << "\n";
	cout << "   Вычислен первообразный корень числа p: g = " << g << "\n";
    cout << "   Cгенерирован закрытый ключ x = " << x << "\n";
    cout << "   Вычислен y = g^x (mod p) = " << y << "\n";
    cout << "   Cгенерировано сообщение M = " << M << "\n";


    cout << "\nПодпись сообщения:\n";
    do {
        k = Random(2, p * 100);
    } while (ExtendedEuclid(k, p-1)[0] != 1);
    a = Exponentiation(g, k, p);
    kobr = ModNegative(ExtendedEuclid(k, p - 1)[1], p - 1);
    b = ModNegative(M - x * a, p - 1) * kobr % (p - 1);
    cout << "   Cгенерировано k взаимнопростое с p-1: k = " << k << "\n";
    cout << "   Вычислен a = g^k (mod p) = " << a << "\n";
    cout << "   Вычислен k^(-1) = " << kobr << "\n";
    cout << "   Вычислен b = (M-xa)*k^(-1) (mod p-1) = " << b << "\n";
    cout << "   Подписью сообщения M является пара (a, b) = (" << a << ", " << b << ")\n";


    cout << "\nПроверка подписи:\n";
    left = Exponentiation(y, a, p) * Exponentiation(a, b, p) % p;
    right = Exponentiation(g, M, p);
    cout << "   y^a * a^b (mod p) = " << left << "\n";
    cout << "   g^M (mod p) = " << right << "\n";
    if (left == right)
        cout << "\nПодпись прошла проверку\n";
    else
        cout << "\nПодпись не прошла проверку\n";
}

int main(int argc, char** argv){
    setlocale(LC_ALL, "Russian");
    int l;
    if (argc == 1) {
        cerr << "Необходимо ввести l - битовую длину числа p\n";
        return 0;
    }
    try {
        l = stoi(argv[1]);
    }
    catch (std::invalid_argument) {
        cerr << "Число l должно быть целым\n";
        return 0;
    }
    if (l < 4) {
        cerr << "Число l должно быть больше 3\n";
        return 0;
    }
    cout << "Протокол электронной цифровой подписи Эль-Гамаля\n";
    Elgamal(l);
    return 0;
}

