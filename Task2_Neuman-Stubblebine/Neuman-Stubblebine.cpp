#include "cryptlib.h"
#include "rijndael.h"
#include "modes.h"
#include "files.h"
#include "osrng.h"
#include "hex.h"

#include <iostream>
#include <string>
#include <random>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <boost/random/variate_generator.hpp>
#include <vector>
#include <time.h>

using namespace std;
using namespace boost::multiprecision;
using namespace boost::random;
using namespace CryptoPP;

cpp_int minim, maxim;
AutoSeededRandomPool prng;
SecByteBlock iv(AES::BLOCKSIZE);


pair <cpp_int, cpp_int> MinMax(int l) {
    cpp_int deg = 2;
    cpp_int maximum = 1;
    for (int i = 2; i <= l; i++) {
        maximum = maximum + deg;
        deg = deg * 2;
    }
    return make_pair(deg / 2, maximum);
}


cpp_int Random() {
    random_device gen;
    boost::random::uniform_int_distribution<cpp_int> ui(minim, maxim);
    return ui(gen);
}


string Encryption(SecByteBlock key, string message) {
    CBC_Mode< AES >::Encryption e;
    e.SetKeyWithIV(key, key.size(), iv);
    string res;
    StringSource s(message, true,
        new StreamTransformationFilter(e,
            new StringSink(res)
        )
    );
    return res;
}


string Decryption(SecByteBlock key, string message) {
    CBC_Mode< AES >::Decryption d;
    d.SetKeyWithIV(key, key.size(), iv);
    string res;
    StringSource s(message, true,
        new StreamTransformationFilter(d,
            new StringSink(res)
        )
    );
    return res;
}


vector <string> UnMess(string mess, int k) {
    string find = " ^ ", prom, resStr;
    vector <string> resVec;
    while (k != 0) {
        prom = {mess[0] , mess[1], mess[2] };
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
    cout << endl;
}


vector <string> FirstPass() {
    string RA = to_string(Random());
    string res = "Alice ^ " + RA;
    return { RA, res };
}


vector <string> SecondPass(string mess, SecByteBlock EB) {
    time_t t;
    t = time(NULL);
    string TB = to_string(t);
    mess = mess + " ^ " + TB;
    string RB = to_string(Random());
    string res = "Bob ^ " + RB + " ^ " + Encryption(EB, mess);
    return { TB, RB, res };
}


vector <string> ThirdPass(string mess, SecByteBlock EB, SecByteBlock EA) {
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());
    string K((const char*)key.data(), key.size());
    vector <string> umess = UnMess(mess, 2);
    string nameBob = umess[0];
    string RB = umess[1];
    vector <string> umessEnc = UnMess(Decryption(EB, umess[2]), 2);
    string nameAlice = umessEnc[0];
    string RA = umessEnc[1];
    string TB = umessEnc[2];
    string res1 = Encryption(EA, nameBob + " ^ " + RA + " ^ " + K + " ^ " + TB);
    string res2 = Encryption(EB, nameAlice + " ^ " + K + " ^ " + TB);
    return { res1 , res2, RB, K };
}


vector <string> FourthPass(vector <string> mess, SecByteBlock EA) {
    vector <string> umess = UnMess(Decryption(EA, mess[0]), 3);
    string RA = umess[1];
    string k = umess[2];
    SecByteBlock K((const byte*)k.data(), k.size());
    string res = Encryption(K, mess[2]);
    return { mess[1], res, k, RA };
}


vector <string> FifthPass(string mess1, string mess2, SecByteBlock EB) {
    vector <string> umess = UnMess(Decryption(EB, mess1), 2);
    string k = umess[1];
    string TB = umess[2];
    SecByteBlock K((const byte*)k.data(), k.size());
    string RB = Decryption(K, mess2);
    return { k, TB, RB };
}


vector <string> Check1Pass(string mess) {
    string RsA = to_string(Random());
    return { RsA, mess };
}


vector <string> Check2Pass(string RsA, string k) {
    string RsB = to_string(Random());
    SecByteBlock K((const byte*)k.data(), k.size());
    return { RsB, Encryption(K, RsA)};
}


vector <string> Check3Pass(string k, string RsB, string mess) {
    SecByteBlock K((const byte*)k.data(), k.size());
    return { Decryption(K, mess), Encryption(K, RsB) };
}


string Check4Pass(string k, string mess) {
    SecByteBlock K((const byte*)k.data(), k.size());
    return Decryption(K, mess);
}


void NeumanStubblebine(int l) {
    prng.GenerateBlock(iv, iv.size());
    pair <cpp_int, cpp_int> minMax = MinMax(l);
    minim = minMax.first;
    maxim = minMax.second;

    //1й проход
    vector <string> resFirstPass = FirstPass();
    cout << "\nАлиса генерирует случайное число Ra = ";
    PrintRes(resFirstPass[0]);
    cout << "И отправляет Бобу сообщение (A, Ra) = ";
    PrintRes(resFirstPass[1]);

    //генерация ключей трентом
    SecByteBlock EA(AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(EA, EA.size());
    SecByteBlock EB(AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(EB, EB.size());

    //2й проход
    vector <string> resSecondPass = SecondPass(resFirstPass[1], EB);
    cout << "\nМетка времени Tb = ";
    PrintRes(resSecondPass[0]);
    cout << "Боб генерирует случайное число Rb = ";
    PrintRes(resSecondPass[1]);
    cout << "И отправляет Тренту сообщение (B, Rb, Eb(A, Ra, Tb))\n   ";
    PrintRes(resSecondPass[2]);

    //3й проход
    vector <string> resThirdPass = ThirdPass(resSecondPass[2], EB, EA);
    cout << "\nТрент генерирует сеансовый ключ K = ";
    PrintRes(resThirdPass[3]);
    cout << "И посылает Алисе следующие сообщения:\n";
    cout << "   Ea(B, Ra, K, Tb) = ";
    PrintRes(resThirdPass[0]);
    cout << "   Eb(A, K, Tb) = ";
    PrintRes(resThirdPass[1]);
    cout << "   Rb = ";
    PrintRes(resThirdPass[2]);

    //4й проход
    vector <string> fourthPass = FourthPass(resThirdPass, EA);
    cout << "\nАлиса извлекает из полученного сообщения:\n";
    cout << "   ключ K = ";
    PrintRes(fourthPass[2]);
    cout << "   своё секретное число Ra = ";
    PrintRes(fourthPass[3]);
    if (resFirstPass[0] == fourthPass[3])
        cout << "   (Случайное число Алисы полученное из сообщения и полученное на первом проходе совпадает)\n";
    else
        cout << "   (Случайное число Алисы полученное из сообщения и полученное на первом проходе не совпадет)\n";
    cout << "Алиса посылает Бобу следующие сообщения:\n";
    cout << "   Eb(A, K, Tb) = ";
    PrintRes(fourthPass[0]);
    cout << "   Ek(Rb) = ";
    PrintRes(fourthPass[1]);

    //5й проход
    vector <string> fifthPass = FifthPass(fourthPass[0], fourthPass[1], EB);
    cout << "\nБоб извлекает из полученных сообщений:\n";
    cout << "   ключ K = ";
    PrintRes(fifthPass[0]);
    cout << "   метку времени Tb = ";
    PrintRes(fifthPass[1]);
    cout << "   своё секретное число Rb = ";
    PrintRes(fifthPass[2]);
    if (fifthPass[1] == resSecondPass[0])
        cout << "   (Временная метка полученная из сообщения и полученная на втором проходе совпадает)\n";
    else
        cout << "   (Временная метка полученная из сообщения и полученная на втором проходе не совпадает)\n";
    if (fifthPass[2] == resSecondPass[1])
        cout << "   (Случайное число Боба полученное из сообщения и полученное на втором проходе совпадает)\n";
    else
        cout << "   (Случайное число Боба полученное из сообщения и полученное на втором проходе не совпадет)\n";
    if (fifthPass[0] == fourthPass[2])
        cout << "\nКлючи, полученные Алисой и Бобом, совпали\n";
    else
        cout << "\nКлючи, полученные Алисой и Бобом, не совпали\n";

    //повторная проверка
    cout << "\n\nПовторная проверка:\n";
    //1
    vector <string> resCheck1Pass = Check1Pass(resThirdPass[1]);
    cout << "Алиса отправляет Бобу сообщения:\n";
    cout << "   Eb(A, K, Tb) = ";
    PrintRes(resCheck1Pass[1]);
    cout << "   R'a = ";
    PrintRes(resCheck1Pass[0]);

    //2
    vector <string> resCheck2Pass = Check2Pass(resCheck1Pass[0], fifthPass[0]);
    cout << "\nБоб отправляет Алисе сообщения:\n";
    cout << "   R'b = ";
    PrintRes(resCheck2Pass[0]);
    cout << "   Ek(R'a) = ";
    PrintRes(resCheck2Pass[1]);

    //3
    vector <string> resCheck3Pass = Check3Pass(fourthPass[2], resCheck2Pass[0], resCheck2Pass[1]);
    cout << "\nАлиса извлекает:\n   R'a = ";
    PrintRes(resCheck3Pass[0]);
    cout << "И отправляет Бобу сообщение:\n";
    cout << "   Ek(R'b) = ";
    PrintRes(resCheck3Pass[1]);

    //4
    string resCheck4Pass = Check4Pass(fifthPass[0], resCheck3Pass[1]);
    cout << "\nБоб извлекает:\n   R'b = ";
    PrintRes(resCheck4Pass);
    if (resCheck3Pass[0] == resCheck1Pass[0])
        cout << "\nПолученное и отправленное R'a совпадает\n";
    else
        cout << "\nПолученное и отправленное R'a не совпадает\n";
    if (resCheck4Pass == resCheck2Pass[0])
        cout << "Полученное и отправленное R'b совпадает\n";
    else
        cout << "Полученное и отправленное R'b не совпадает\n";
}


int main(int argc, char* argv[]) {
    setlocale(LC_ALL, "Russian");
    int l;
    if (argc == 1) {
        cerr << "Необходимо ввести l - битовую длину случайных чисел Алисы и Боба\n";
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
    cout << "Протокол Neuman-Stubblebine\n";
    NeumanStubblebine(l);
    return 0;
}