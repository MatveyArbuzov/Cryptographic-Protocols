#include <iostream>
#include <string>
#include "osrng.h"
#include "dsa.h"
#include "dh.h"
#include <random>
#include "files.h"
#include <set>
#include <hex.h>
#include "rsa.h"
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
        cpp_int x = Exponentiation(a, t, p);
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


string Encryption(RSA::PublicKey key, string message) {
    string res;
    RSAES_OAEP_SHA_Encryptor e(key);
    StringSource ss1(message, true,
        new PK_EncryptorFilter(rng, e,
            new StringSink(res)
        )
    ); 
    return res;
}


string Decryption(RSA::PrivateKey key, string message) {
    string res;
    RSAES_OAEP_SHA_Decryptor d(key);
    StringSource ss2(message, true,
        new PK_DecryptorFilter(rng, d,
            new StringSink(res)
        )
    );
    return res;
}


vector <string> UnMess(string mess, int k) {
    string find = " ^ ", prom, resStr;
    vector <string> resVec;
    while (k != 0) {
        prom = { mess[0] , mess[1], mess[2] };
        if (prom == find) {
            mess.erase(0, 3);
            resVec.push_back(resStr);
            resStr.clear();
            k--;
        }
        else {
            resStr = resStr + mess[0];
            mess.erase(0, 1);
        }
    }
    resVec.push_back(mess);
    return resVec;
}


void PrintRes(string str) {
    HexEncoder encoder(new FileSink(cout));
    encoder.Put((const byte*)&str[0], str.size());
    encoder.MessageEnd();
}


void Encode(const BufferedTransformation& bt){
    HexEncoder encoder(new FileSink(cout));
    bt.CopyTo(encoder);
    encoder.MessageEnd();
}


void EncodePublicKey(const RSA::PublicKey& key){
    ByteQueue queue;
    key.DEREncodePublicKey(queue);
    Encode(queue);
}


void EncodePrivateKey(const RSA::PrivateKey& key) {
    ByteQueue queue;
    key.DEREncodePrivateKey(queue);
    Encode(queue);
}


void CountingOfVotes(vector< vector<pair <cpp_int, string>>> bulletin, vector< pair <cpp_int, RSA::PrivateKey>> keys, int p) {
    vector< vector <string>> result(p);
    for (int i = 0; i < bulletin.size(); i++) {
        if (bulletin[i].size() == 2) {
            if (bulletin[i][1].first == keys[i].first) {
                string messDe2 = Decryption(keys[i].second, bulletin[i][1].second);
                vector <string> SbAndV2 = UnMess(messDe2, 1);
                cpp_int SbDe2(SbAndV2[0]);
                int choiceDe2 = stoi(SbAndV2[1]);
                if (SbDe2 == bulletin[i][1].first) {
                    string messDe1 = Decryption(keys[i].second, bulletin[i][0].second);
                    vector <string> SbAndV1 = UnMess(messDe1, 1);
                    cpp_int SbDe1(SbAndV1[0]);
                    int choiceDe1 = stoi(SbAndV1[1]);
                    if (SbDe1 == bulletin[i][0].first)
                        result[choiceDe2 - 1].push_back(bulletin[i][1].second);
                }
            }
        }
        else {
            if (bulletin[i][0].first == keys[i].first) {
                string messDe = Decryption(keys[i].second, bulletin[i][0].second);
                vector <string> SbAndV = UnMess(messDe, 1);
                cpp_int SbDe(SbAndV[0]);
                int choiceDe = stoi(SbAndV[1]);
                if (SbDe == bulletin[i][0].first)
                    result[choiceDe - 1].push_back(bulletin[i][0].second);
            }
        }
    }
    for (int i = 0; i < result.size(); i++) {
        cout << "\n      Количество голосов за кандидата " << i + 1 << ": " << result[i].size();
        for (int j = 0; j < result[i].size(); j++) {
            cout << "\n         ";
            PrintRes(result[i][j]);
        }
        cout << "\n";
    }
}


void VotingOnANDOS(int n, int p) {
    
    //Публикация всех возможных избирателей
    cout << "\n   ЦИК:";
    cout << "\n      Публикует список всех правомочных избирателей:\n         ";
    for (int i = 0; i < n; i++)
            cout << i + 1 << " ";

    //Избиратели, которые хотят голосовать
    cout << "\n      Публикует список избирателей, собирающихся принять участие в голосовании:\n         ";
    vector <int> voters;
    for (int i = 0; i < n; i++)
        if (rand() % 2 == 1) {
            voters.push_back(i);
            cout << i + 1 << " ";
        }

    //Генерация идентификаторов (простые числа)
    set<cpp_int> setS;
    vector<cpp_int> vecS;
    DH dh;
    while (setS.size() != n) {
        int sizeS = setS.size();
        dh.AccessGroupParameters().GenerateRandomWithKeySize(rng, rand() % 21 + 4);
        cpp_int prom = IntegerToCppint(dh.GetGroupParameters().GetModulus());
        setS.insert(prom);
        if (setS.size() != sizeS)
            vecS.push_back(prom);
    }
    cout << "\n      Генерирует идентификаторы:\n";
    for (int i = 0; i < vecS.size(); i++)
        cout << "         S" << i + 1 << ": " << vecS[i] << "\n";

    //Генерация ключей RSA для ЦИК
    InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, 25);
    cpp_int nA = IntegerToCppint(params.GetModulus());
    cpp_int eA = IntegerToCppint(params.GetPublicExponent());
    cpp_int dA = IntegerToCppint(params.GetPrivateExponent());
    cout << "      Генерирует ключи RSA:\n         e = " << eA << "\n         d = " << dA;

    //Шифрование идентификаторов открытым ключом RSA
    vector<cpp_int> vecC;
    for (int i = 0; i < vecS.size(); i++)
        vecC.push_back(Exponentiation(vecS[i], eA, nA));
    cout << "\n      Шифрует идентификаторы открытым ключом RSA:\n";
    for (int i = 0; i < vecC.size(); i++)
        cout << "         C" << i + 1 << ": " << vecC[i] << "\n";

    //Голосование
    set<cpp_int> usedS;
    vector< vector<pair <cpp_int, string>>> bulletin;
    vector< pair <cpp_int, RSA::PrivateKey>> keys;
    for (int i = 0; i < voters.size(); i++) {

        //Получение идентификатора
        cout << "\n\n   Голосующий " << voters[i] + 1 << ":\n";
        int b = rand() % n;
        cout << "      Выбрал C" << b + 1 << ": " << vecC[b];
        cpp_int r = Random(2, nA - 1);
        while (ExtendedEuclid(r, nA)[0] != 1)
            r = Random(1, nA - 1);
        cout << "\n      Выбрал случайное число r = " << r;
        cpp_int Csh = (vecC[b] * Exponentiation(r, eA, nA)) % nA;
        cout << "\n      Вычислил и отправил ЦИК значение С' = С" << b + 1 << " * r^e (mod n) = " << Csh;
        

        cout << "\n\n   ЦИК:";
        cpp_int Psh = Exponentiation(Csh, dA, nA);
        cout << "\n      Вычислил и отправил голосующему P' = С'^d (mod n) = " << Psh;


        cout << "\n\n   Голосующий " << voters[i] + 1 << ":\n";
        cpp_int Sb = (Psh * ModNegative(ExtendedEuclid(r, nA)[1], nA)) % nA;
        cout << "      Получил идентификатор S" << b + 1 << " = " << Sb << " с помощью выражения P' * r^-1 (mod n)";

        //генерация ключей голосующим
        params.GenerateRandomWithKeySize(rng, 512);
        RSA::PrivateKey d(params);
        RSA::PublicKey k(params);
        cout << "\n      Сгенерировал открытый ключ k:\n         ";
        EncodePublicKey(k);
        cout << "\n      Сгенерировал закрытый ключ d:\n         ";
        EncodePrivateKey(d);

        //Выбор кандидата
        int choice = rand();
        choice = choice % p + 1;
        cout << "\n      Выбрал кандидата: " << choice;

        //Шифрование и отправка сообщения
        string mess = to_string(Sb) + " ^ " + to_string(choice);
        string messEn = Encryption(k, mess);
        cout << "\n      Отправил ЦИК пару (S" << b + 1 << ", Ek(S" << b + 1 << ", v)):\n         (" << Sb << ", "; 
        PrintRes(messEn);
        cout << ")";
        
        //Подтверждение получения
        int sizeUS = usedS.size();
        usedS.insert(Sb);
        bool checker = true;
        bulletin.push_back({ make_pair(Sb, messEn) });
        //Идентификатр совпал
        if (sizeUS == usedS.size()) {
            //Новый идентификатор
            int sizeS = setS.size();
            cpp_int Ssh;
            while (setS.size() == sizeS) {
                dh.AccessGroupParameters().GenerateRandomWithKeySize(rng, rand() % 21 + 4);
                Ssh = IntegerToCppint(dh.GetGroupParameters().GetModulus());
                setS.insert(Ssh);
            }
            cout << "\n\n   ЦИК публикует пару (S', Ek(S" << b + 1 << ", v), так как выбранный идентификатор занят:\n      (" << Ssh << ", ";
            PrintRes(messEn);
            cout << ")";
            
            //Новая отправка голосующего
            cout << "\n\n   Голосующий " << voters[i] + 1 << ":";
            mess = to_string(Ssh) + " ^ " + to_string(choice);
            messEn = Encryption(k, mess);
            cout << "\n      Отправил ЦИК пару (S', Ek(S', v)):\n         (" << Ssh << ", ";
            PrintRes(messEn);
            cout << ")";
            Sb = Ssh;
            usedS.insert(Sb);
            bulletin[bulletin.size()-1].push_back(make_pair(Sb, messEn));
            checker = false;
        }

        //Теперь идентификатор в порядке
        if (checker)
            cout << "\n\n   ЦИК публикует Ek(S" << b + 1 << ", v):\n      ";
        else
            cout << "\n\n   ЦИК публикует Ek(S', v):\n      ";
        PrintRes(messEn);

        //Голосующий отправляет ключ
        if (checker)
            cout << "\n\n   Голосующий " << voters[i] + 1 << " отправил ЦИК пару (S" << b + 1 << ", d):\n      (" << Sb << ", ";
        else
            cout << "\n\n   Голосующий " << voters[i] + 1 << " отправил ЦИК пару (S', d):\n      (" << Sb << ", ";
        EncodePrivateKey(d);
        cout << ")\n";
        keys.push_back(make_pair(Sb, d));
    }
    
    //Результат голосования
    cout << "\n\n   Результат голосования:";
    CountingOfVotes(bulletin, keys, p);
}


void ErrMess() {
    cerr << "   На входе должны быть следующие параметры:\n"
        << "      n - число избирателей \n"
        << "      p - число претендентов\n";
}


int main(int argc, char** argv) {
    setlocale(LC_ALL, "Russian");
    srand(time(NULL));
    if (argc < 3) {
        cerr << "\n   Ошибка: Недостаточное количество параметров\n";
        ErrMess();
        return 0;
    }
    int n = -1, p = -1;
    string prom1, prom2;
    for (int i = 1; i < argc; i++) {
        prom1 = argv[i];
        try {
            prom1.erase(2, prom1.size() - 2);
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
            if (prom1 == "p=") {
                prom2 = argv[i];
                prom2.erase(0, 2);
                try {
                    p = stoi(prom2);
                }
                catch (exception) {
                    cerr << "\n   Ошибка в параметре p: передано некорректное число\n";
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
    if (n < 0 || p < 0) {
        cerr << "\n   Ошибка: некоторые параметры отсутствуют или пустые\n";
        ErrMess();
        return 0;
    }
    if (n < 1) {
        cerr << "\n   Ошибка в параметре n: должно быть должно быть больше 0\n";
        return 0;
    }
    if (p < 1) {
        cerr << "\n   Ошибка в параметре p: должно быть должно быть больше 0\n";
        return 0;
    }
    cout << "Протокол голосования с одной центральной комиссией на базе протокола ANDOS\n";
    VotingOnANDOS(n, p);
    return 0;
}

