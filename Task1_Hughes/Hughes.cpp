#include <iostream>
#include <random>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <boost/random/variate_generator.hpp>
#include <vector>


using namespace std;
using namespace boost::multiprecision;
using namespace boost::random;


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


cpp_int Jac(cpp_int a, cpp_int b) {
    if (ExtendedEuclid(a, b)[0] != 1)
        return 0;
    else {
        int r = 1;
        while (a != 0) {
            cpp_int t = 0;
            while (a % 2 == 0) {
                t = t + 1;
                a = a / 2;
            }
            if (t % 2 != 0)
                if (Exponentiation(b, 1, 8) == 3 || Exponentiation(b, 1, 8) == 5)
                    r = r * (-1);
            if (Exponentiation(a, 1, 4) == 3 && Exponentiation(b, 1, 4) == 3)
                r = r * (-1);
            cpp_int c = a;
            if (c != 0)
                a = Exponentiation(b, 1, c);
            b = c;
        }
        return r;
    }
}


bool SolovSht(cpp_int p, int k) {
    if (p > 0 && p < 4)
        return true;
    if (p % 2 == 0)
        return false;
    for (int i = 0; i < k; i++) {
        cpp_int a = rand() % (p - 2) + 2;
        if (ExtendedEuclid(p, a)[0] > 1)
            return false;
        cpp_int t = (p - 1) / 2;
        cpp_int newa = Exponentiation(a, t, p);
        cpp_int l = Jac(a, p);
        if (l == -1)
            l = p - 1;
        if (newa != l)
            return false;
    }
    return true;
}


cpp_int GenN(int l) {
    for (;;) {
        srand(time(0));
        cpp_int n = 1;
        cpp_int deg = 2;
        for (int i = 1; i < l - 1; i++) {
            n = n + (deg * (rand() % 2));
            deg = deg * 2;
        }
        n = n + deg;
        if (SolovSht(n, 10))
            return n;
    }
}


cpp_int random(cpp_int start, cpp_int p) {
    random_device gen;
    boost::random::uniform_int_distribution<cpp_int> ui(start, p - 1);
    return ui(gen);
}


vector <cpp_int> Divis(cpp_int n){
    vector <cpp_int> res;
    for (cpp_int i = 1; i < n / 2 + 1; i++)
        if (n % i == 0)
            res.push_back(i);
    res.push_back(n);
    return res;
}


bool Primitive(cpp_int n, cpp_int g) {
    vector <cpp_int> divisors = Divis(n - 1);
    for (int i = 0; i < divisors.size(); i++)
        if (Exponentiation(g, divisors[i], n) == 1)
            if (divisors[i] == n - 1)
                return true;
            else
                break;
    return false;
}


cpp_int GenG(cpp_int n) {
    cpp_int g;
    for (;;) {
        g = random(0, n);
        if (SolovSht(g, 10) && Primitive(n, g))
            return g;
    }
}


pair <cpp_int, cpp_int> FirstPass(cpp_int n, cpp_int g) {
    pair <cpp_int, cpp_int> res;
    cpp_int x = random(2, n);
    cpp_int k = Exponentiation(g, x, n);
    res = make_pair(x, k);
    return res;
}


pair <cpp_int, cpp_int> SecondPass(cpp_int n, cpp_int g) {
    pair <cpp_int, cpp_int> res;
    cpp_int y, q = n - 1;
    while (q % 2 == 0)
        q = q / 2;
    for (;;) {
        y = random(2, n);
        if (ExtendedEuclid(y, n - 1)[0] == 1)
            if (y != q)
                break;
    }
    cpp_int Y = Exponentiation(g, y, n);
    res = make_pair(y, Y);
    return res;
}


cpp_int ThirdPass(cpp_int Y, cpp_int x, cpp_int n) {
    cpp_int X = Exponentiation(Y, x, n);
    return X;
}


pair <cpp_int, cpp_int> FourthPass(cpp_int y, cpp_int X, cpp_int n) {
    pair <cpp_int, cpp_int> res;
    cpp_int z = ExtendedEuclid(y, n - 1)[1];
    while (z < 0)
        z = (z + n - 1);
    cpp_int k = Exponentiation(X, z, n);
    res = make_pair(z, k);
    return res;
}


void Hughes(int l) {
    cpp_int n = GenN(l);
    cout << "n = " << n << "\n";
    cpp_int g = GenG(n);
    cout << "g = " << g << "\n";
    pair <cpp_int, cpp_int> xk = FirstPass(n, g);
    cout << "Алиса сгенерировала числа x = " << xk.first << " и k = " << xk.second << "\n";
    pair <cpp_int, cpp_int> yY = SecondPass(n, g);
    cout << "Боб сгенерировал y = " << yY.first << " и послал Алисе Y = " << yY.second << "\n";
    cpp_int X = ThirdPass(yY.second, xk.first, n);
    cout << "Алиса посылает Бобу X = " << X << "\n";
    pair <cpp_int, cpp_int> zksh = FourthPass(yY.first, X, n);
    cout << "Боб вычислил z = " << zksh.first << " и сгенерировал k' = " << zksh.second << "\n";
}


int main(int argc, char* argv[]) {
    setlocale(LC_ALL, "Russian");
    int l;
    if (argc == 1){
        cerr << "Необходимо ввести l - длину числа n\n";
        return 0;
    }
    try {
        l = stoi(argv[1]);
    }
    catch (std::invalid_argument) {
        cerr << "Число l должно быть целым\n";
        return 0;
    }
    if (l < 2) {
        cerr << "Число l должно быть больше 1\n";
        return 0;
    }
    Hughes(l);
    return 0;
}