#include <iostream>
#include <string>
#include "osrng.h"
#include "dsa.h"
#include "dh.h"
#include <random>
#include "files.h"
#include <set>
#include <hex.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random/uniform_int.hpp>
#include <boost/random/variate_generator.hpp>
#include <boost/multiprecision/cpp_dec_float.hpp>


using namespace CryptoPP;
using namespace std;
using namespace boost::multiprecision;
using namespace boost::random;


AutoSeededRandomPool rng;


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


cpp_int Exponentiation(cpp_int x, cpp_int n, cpp_int m, int k) {
    cpp_int N = n, Y = 1, Z = x;
    if (k == 1)
        Z = Z % m;
    else
        N--;
    while (N != 0) {
        cpp_int lastN = N % 2;
        N = N / 2;
        if (lastN == 0) {
            Z = (Z * Z);
            if (k == 1)
                Z = Z % m;
            continue;
        }
        Y = (Y * Z);
        if (k == 1)
            Y = Y % m;
        if (N == 0)
            break;
        Z = (Z * Z);
        if (k == 1)
            Z = Z % m;
    }
    if (k == 1)
        Y = Y % m;
    return Y;
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
                if (Exponentiation(b, 1, 8, 1) == 3 || Exponentiation(b, 1, 8, 1) == 5)
                    r = r * (-1);
            if (Exponentiation(a, 1, 4, 1) == 3 && Exponentiation(b, 1, 4, 1) == 3)
                r = r * (-1);
            cpp_int c = a;
            if (c != 0)
                a = Exponentiation(b, 1, c, 1);
            b = c;
        }
        return r;
    }
}


bool MilRab(cpp_int p, cpp_int k) {
    if (p == 1 || p == 2 || p == 3)
        return true;
    if (p % 2 == 0)
        return false;
    cpp_int t = p - 1;
    cpp_int s = 0;
    while (t % 2 == 0) {
        t = t / 2;
        s++;
    }
    for (cpp_int i = 0; i < k; i++) {
        cpp_int a = rand() % (p - 3) + 2;
        if (ExtendedEuclid(p, a)[0] > 1)
            return false;
        cpp_int x = Exponentiation(a, t, p, 1);
        if (x == 1 || x == p - 1)
            continue;
        for (cpp_int g = 1; g < s; g++) {
            x = x * x % p;
            if (x == 1)
                return false;
            if (x == p - 1)
                break;
        }
        if (x != p - 1)
            return false;
    }
    return true;
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


cpp_int GenMess(int l) {
    cpp_int m = 1;
    cpp_int deg = 2;
    for (int i = 1; i < l - 1; i++) {
        m = m + (deg * (rand() % 2));
        deg = deg * 2;
    }
    m = m + deg;
    return m;
}


cpp_int toSHA1(string mess) {
    string digest, res;
    SHA1 hash;
    hash.Update((const byte*)mess.data(), mess.size());
    digest.resize(hash.DigestSize());
    hash.Final((byte*)&digest[0]);
    StringSource(digest, true, new HexEncoder(new StringSink(res)));
    istringstream stream(res);
    cpp_int dec;
    stream >> hex >> dec;
    return dec;
}


vector <cpp_int> toBits(cpp_int n) {
    vector <cpp_int> res1, res2;
    while (n > 1) {
        res1.push_back(n % 2);
        n = n / 2;
    }
    res1.push_back(n);
    for (int i = res1.size() - 1; i > -1; i--)
        res2.push_back(res1[i]);
    return res2;
}


bool checkSignature(cpp_int s, cpp_int q, cpp_int H, cpp_int r, cpp_int g, cpp_int p, cpp_int y, bool check, string str) {
    cpp_int u = ModNegative(ExtendedEuclid(s, q)[1], q);
    cpp_int a = (H * u) % q;
    cpp_int b = (r * u) % q;
    cpp_int prom1 = Exponentiation(g, a, p, 1);
    cpp_int prom2 = Exponentiation(y, b, p, 1);
    cpp_int v = ((prom1 * prom2) % p) % q;
    if (check) {
        cout << "\n   Проверка подписи " << str << "ом:\n";
        cout << "      Вычисление u = s^-1 (mod q) = " << u << "\n";
        cout << "      Вычисление a = H(m) * u (mod q) = " << a << "\n";
        cout << "      Вычисление b = r * u (mod q) = " << b << "\n";
        cout << "      Вычисление v = (g^a * y^b mod p) mod q = " << v << "\n";
        if (r == v)
            cout << "      " << str << " убедился, в подлинности сообщения (r = v)\n";
    }
    if (r == v)
        return true;
    return false;
}


void SecretChannelDSA(int l, int sizem, int iter) {

    //Сообщения
    cpp_int m, msh, H;
    m = GenMess(sizem);
    H = toSHA1(to_string(m));
    msh = GenMess(sizem);
    vector <cpp_int> bitsMsh = toBits(msh);
    cout << "\nГенерация сообщений:\n";
    cout << "   m - безобидное сообщение: " << m;
    cout << "\n   H(m) - значение хэш функции от m: " << H;
    cout << "\n   m' - секретное сообщение: " << msh << " = ";
    for (int i = 0; i < bitsMsh.size(); i++)
        cout << bitsMsh[i];

    //p и q
    DH dh1; cpp_int p , q;
    cpp_int deg = Exponentiation(2, l - 160, 1, 2);
    for (;;) {
        do {
            dh1.AccessGroupParameters().GenerateRandomWithKeySize(rng, 160);
            q = IntegerToCppint(dh1.GetGroupParameters().GetModulus());
        } while (H >= q);
        p = deg * q + 1;
        if (MilRab(p, 10))
            break;
    }
    cout << "\n\nГенерация основных параметров:\n";
    cout << "   p - " << l << " битовое простое число: " << p;
    cout << "\n\n   q - " << 160 << " битовый простой множитель числа p-1: " << q;
    
    //генерация h и g
    cpp_int h = 2, g;
    do {
        g = Exponentiation(h, (p - 1) / q, p, 1);
        if (Exponentiation(g, q, p, 1) != 1) {
            g = 0;
            h = Random(2, p - 2);
            continue;
        }
    } while (g < 2);
    cout << "\n\n   h - случайное число, меньше чем p-1: " << h;
    cout << "\n\n   g = h^((p-1)/q) (mod p): " << g << "\n";

    //генерация P
    cpp_int P = p;
    DH dh;
    while (p == P) {
        dh.AccessGroupParameters().GenerateRandomWithKeySize(rng, rand() % 1020 + 4);
        P = IntegerToCppint(dh.GetGroupParameters().GetModulus());
    }
    cout << "\n   P - секретный ключ Алисы и Боба для скрытого канала (простое число, отличное от p): " << P;

    //открытый и закрытый ключ Алисы
    DH dh2;
    cpp_int x, y;
    x = Random(1, q - 1);
    y = Exponentiation(g, x, p, 1);
    cout << "\n\n   x - закрытый ключ Алисы: " << x;
    cout << "\n\n   y = g^x (mod p) - открытый ключ Алисы: " << y << "\n";

    //Протокол
    cout << "\nПередача секретного сообщения:";
    iter--;
    vector <cpp_int> bitsBob;
    for (int i = 0; i < bitsMsh.size();) {
        //Алиса
        cpp_int k = Random(1, q - 1);
        if (ExtendedEuclid(k, q)[0] != 1)
            continue;
        cpp_int r = Exponentiation(g, k, p, 1) % q;
        if (bitsMsh[i] == 1) {
            if (Jac(r, P) != 1)
                continue;
        }
        else{
            if (Jac(r, P) != -1)
                continue;
        }
        if (r == 0)
            continue;
        cpp_int s = (ModNegative(ExtendedEuclid(k, q)[1], q) * (H + x * r)) % q;
        if (s == 0 || ExtendedEuclid(s, q)[0] != 1)
            continue;
        bool checkIter = iter >= i;
        if (checkIter) {
            cout << "\n\n   Генерация подписи Алисой:";
            cout << "\n      Генерация случайного числа k = " << k;
            cout << "\n      Вычисление r = (g^k mod p) (mod q) = " << r;
            cout << "\n      Вычисление s = (k^-1 * (H(m) + xr)) (mod q) = " << s;
            cout << "\n\n   Алиса передаёт вместе с Уолтером сообщение m и подпись (r,s)\n";
        }
        //Уолтер
        bool checkSignW = checkSignature(s, q, H, r, g, p, y, iter >= i, "Уолтер");
        if (checkSignW) {
            if (checkIter)
                cout << "\n   Уолтер передал Бобу сообщение и подпись Алисы\n";
            //Боб
            bool checkSignB = checkSignature(s, q, H, r, g, p, y, iter >= i, "Боб");
            if (checkSignB) {
                cpp_int quad = Jac(r, P);
                cpp_int bitBob;
                if (quad == 1)
                    bitBob = 1;
                if (quad == -1)
                    bitBob = 0;
                cout << "\n   Алиса отправила " << bitsMsh[i] << ", Боб получил " << bitBob;
                bitsBob.push_back(bitBob);
            }
        }
        i++;
    }
    cout << "\n\nВ итоге, Боб получил: ";
    for (int i = 0; i < bitsBob.size(); i++)
        cout << bitsBob[i];
    cout << "\n";
}


void ErrMess() {
    cerr << "   На входе должны быть следующие параметры:\n"
        << "      l - битовая длина числа p\n"
        << "      s - битовая длина секретного сообщения\n"
        << "      i - сколько итераций необходимо подробно описать\n";
}


int main(int argc, char** argv) {
    setlocale(LC_ALL, "Russian");
    srand(time(NULL));
    if (argc < 2) {
        cerr << "\n   Ошибка: Недостаточное количество параметров\n";
        ErrMess();
        return 0;
    }
    int s = -1, l = -1, iter = -1;
    string prom1, prom2;
    for (int i = 1; i < argc; i++) {
        prom1 = argv[i];
        try {
            prom1.erase(2, prom1.size() - 2);
            if (prom1 == "l=") {
                prom2 = argv[i];
                prom2.erase(0, 2);
                try {
                    l = stoi(prom2);
                }
                catch (exception) {
                    cerr << "\n   Ошибка в параметре l: передано некорректное число\n";
                    ErrMess();
                    return 0;
                }
                continue;
            }
            if (prom1 == "s=") {
                prom2 = argv[i];
                prom2.erase(0, 2);
                try {
                    s = stoi(prom2);
                }
                catch (exception) {
                    cerr << "\n   Ошибка в параметре s: передано некорректное число\n";
                    ErrMess();
                    return 0;
                }
                continue;
            }
            if (prom1 == "i=") {
                prom2 = argv[i];
                prom2.erase(0, 2);
                try {
                    iter = stoi(prom2);
                }
                catch (exception) {
                    cerr << "\n   Ошибка в параметре i: передано некорректное число\n";
                    ErrMess();
                    return 0;
                }
                continue;
            }
        }
        catch (exception) {
            continue;
        }
    }
    if (l < 0 || s < 0 || iter < 0) {
        cerr << "\n   Ошибка: некоторые параметры отсутствуют или пустые\n";
        ErrMess();
        return 0;
    }
    if (l < 512 || l > 1024 || l % 64 != 0) {
        cerr << "\n   Ошибка в параметре l: должно быть в диапозоне от 512 до 1024 и делиться на 64\n";
        return 0;
    }
    if (s < 1) {
        cerr << "\n   Ошибка в параметре s: должно быть больше 0\n";
        return 0;
    }
    if (iter < 0 || iter > s) {
        cerr << "\n   Ошибка в параметре i: должно быть в диапозоне от 0 до " << s << "\n";
        return 0;
    }
    cout << "Скрытый канал связи на основе DSA\n";
    SecretChannelDSA(l, s, iter);
    return 0;
}

