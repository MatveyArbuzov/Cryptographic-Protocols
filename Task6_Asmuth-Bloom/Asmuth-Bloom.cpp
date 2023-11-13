#include <iostream>
#include <string>
#include "osrng.h"
#include "rsa.h"
#include <random>
#include <set>
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


int BitLength(cpp_int M) {
    cpp_dec_float_50 prom = log2(cpp_dec_float_50(M) + 1);
    cpp_int res(prom);
    if (prom - cpp_dec_float_50(res) != 0)
        res++;
    string s = to_string(res);
    return stoi(s);
}


cpp_int SystemTh(vector <cpp_int> ms, vector <cpp_int> us, cpp_int M) {
    cpp_int u = 0;
    vector <cpp_int> c, d;
    for (int i = 0; i < ms.size(); i++) {
        c.push_back(M / ms[i]);
        d.push_back(ExtendedEuclid(c[i], ms[i])[1]);
        u = (u + c[i] * d[i] * us[i]);
        u = ModNegative(u, M) % M;
    }
    return u;
}


void AsmutBloom(cpp_int M, int n, int m) {
    cout << "\n   Секрет M = " << M << "\n";
    cout << "   Число участников n = " << n << "\n";
    cout << "   Минимальное число участников, нужное для восстановления секрета, m = " << m << "\n";

    //Генерация p
    int sizeM = BitLength(M);
    if (sizeM < 16)
        sizeM = 15;
    cpp_int p;
    InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, (sizeM * 2) + 1);
    p = IntegerToCppint(params.GetPrime1());
    cout << "\n   Было сгенерированно p = " << p << "\n";

    //Генерация di
    bool checker = true;
    set<cpp_int> diSet;
    vector<cpp_int> diVector;
    while (checker) {
        diSet.clear();
        diVector.clear();

        // di > p и di < di+1
        while (diSet.size() < n) {
            params.GenerateRandomWithKeySize(rng, (sizeM * 2) + 2);
            diSet.insert(IntegerToCppint(params.GetPrime1()));
        }

        //Проверка последнего условия
        cpp_int m1 = m;
        cpp_int left = 1, right = p;
        for (cpp_int di : diSet)
            diVector.push_back(di);
        for (int i = 0; i < diVector.size(); i++) {
            if (m1 == 0) {
                right = right * diVector[i];
                continue;
            }
            left = left * diVector[i];
            m1--;
            if (m1 == 0)
                i = diVector.size() - m + 1;
        }
        if (left > right)
            checker = false;
    }

    //Генерация r и вычисление M' 
    cpp_int diMult = 1;
    for (int i = 0; i < m - 1; i++)
        diMult = diMult * diVector[i];
    cpp_int r, Msh;
    do {
        r = Random(2, diMult);
        Msh = M + r * p;
    } while (Msh <= diMult);
    cout << "   Было сгенерированно r = " << r << "\n";
    cout << "   Было вычисленно M' = M + rp = " << Msh << "\n";

    //Вычисление долей ki
    vector<cpp_int> kiVector;
    for (int i = 0; i < diVector.size(); i++)
        kiVector.push_back(Msh % diVector[i]);

    cout << "   После выбора di и вычисления долей ki = M' mod di участникам были разданы {p, di, ki}:\n";
    for (int i = 0; i < diVector.size(); i++)
        cout << "      Участник " << i + 1 << ": {" << p << ", " << diVector[i] << ", " << kiVector[i] << "}\n";

    //Восстановление секрета
    string answer;
    for (;;) {
        cout << "\n   Запустить дефолтное (m = " << m << ", участники выбираются случайно) восстановление секрета? [y,n]: ";
        cin >> answer;
        if (answer != "n" && answer != "y")
            break;
        set <int> participants;
        vector <cpp_int> diUsed, kiUsed;
        cpp_int diMultUsed = 1, MshSekret, MSekret;
        int newm, participant;
        if (answer == "y") {
            while (participants.size() != m)
                participants.insert(rand() % n);
        }
        else {
            for (;;) {
                cout << "      Введите новое m: ";
                try {
                    cin >> newm;
                }
                catch (exception) {
                    cerr << "\n   Введены некорректные данные";
                    continue;
                }
                if (newm > 1 && newm < n + 1)
                    break;
            }
            cout << "      Введите разных участников от 1 до " << n << ": ";
            while (participants.size() != newm) {
                try {
                    cin >> participant;
                }
                catch (exception) {
                    cerr << "\n   Введены некорректные данные";
                    continue;
                }
                if (participant < 0 || newm > n)
                    continue;
                participants.insert(participant - 1);
            }
        }
        cout << "      Участники ";
        for (int i : participants) {
            cout << i + 1 << " ";
            diUsed.push_back(diVector[i]);
            kiUsed.push_back(ModNegative(ExtendedEuclid(kiVector[i], diVector[i])[1], diVector[i]));
        }
        cout << "хотят восстановить секрет\n";
        for (int i = 0; i < diUsed.size(); i++)
            diMultUsed = diMultUsed * diUsed[i];
        MshSekret = SystemTh(diUsed, kiUsed, diMultUsed);
        MshSekret = ModNegative(ExtendedEuclid(MshSekret, diMultUsed)[1], diMultUsed);
        cout << "         Участники получили M' = " << MshSekret << "\n";
        MSekret = MshSekret % p;
        cout << "         Участники вычислили M = M'(mod p) = " << MSekret << "\n";

        if (M == MSekret)
            cout << "\n   M, разделённое в начале, сопало с M, полученным в конце\n";
        else
            cout << "\n   M, разделённое в начале, не сопало с M, полученным в конце\n";
    }
}

void ErrMess() {
    cerr << "   На входе должны быть следующие параметры:\n"
        << "      M - число, являющееся секретом\n"
        << "      n - число сторон, разделяющих секрет\n"
        << "      m - число участников, восстанавливающих секрет\n";
}


int main(int argc, char** argv) {
    setlocale(LC_ALL, "Russian");
    int l;
    cout << "Разделение секрета: схема Асмута-Блума\n";
    srand(time(NULL));
    if (argc < 4) {
        cerr << "\n   Ошибка: Недостаточное количество параметров\n";
        ErrMess();
        return 0;
    }
    cpp_int M = -1;
    int m = -1, n = -1;
    string prom1, prom2;
    for (int i = 1; i < argc; i++) {
        prom1 = argv[i];
        try {
            prom1.erase(2, prom1.size() - 2);
            if (prom1 == "M=") {
                prom2 = argv[i];
                prom2.erase(0, 2);
                try {
                    cpp_int promM(prom2);
                    M = promM;
                }
                catch (exception) {
                    cerr << "\n   Ошибка в параметре M: передано некорректное число\n";
                    ErrMess();
                    return 0;
                }
                continue;
            }
            if (prom1 == "n=") {
                prom2 = argv[i];
                prom2.erase(0, 2);
                try {
                    n = stoi(prom2);
                }
                catch (exception) {
                    cerr << "\n   Ошибка в параметре n: передано некорректное число\n";
                    ErrMess();
                    return 0;
                }
                continue;
            }
            if (prom1 == "m=") {
                prom2 = argv[i];
                prom2.erase(0, 2);
                try {
                    m = stoi(prom2);
                }
                catch (exception) {
                    cerr << "\n   Ошибка в параметре m: передано некорректное число\n";
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
    if (M < 0 || m < 0 || n < 0) {
        cerr << "\n   Ошибка: некоторые параметры отсутствуют или пустые\n";
        ErrMess();
        return 0;
    }
    if (M < 1) {
        cerr << "\n   Ошибка в параметре M: должно быть больше 0\n";
        return 0;
    }
    if (n < 2) {
        cerr << "\n   Ошибка в параметре n: должно быть больше 1\n";
        return 0;
    }
    if (m < 2 || m > n) {
        cerr << "\n   Ошибка в параметре m: должно быть больше 1 и непревосходить n\n";
        return 0;
    }
    AsmutBloom(M, n, m);
    return 0;
}


