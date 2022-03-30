#include <iostream>
#include <map>
#include <string> 

//файлы для подключения библиотеки Crypto++
#include "../cryptopp860/cryptlib.h"
#include "../cryptopp860/des.h" // DES algorithm
#include "../cryptopp860/modes.h"
#include "../cryptopp860/filters.h"
#include "../cryptopp860/osrng.h" // PNG AutoSeededX917RNG
#include "../cryptopp860/sha.h" 
#include "../cryptopp860/base64.h"

using namespace CryptoPP;
using namespace std;

const unsigned int BLOCKSIZE = 64;

//функция хеширования sha256 с выводом base64
string SHA256HashString(string aString) {
    string digest;
    SHA256 hash;

    StringSource foo(aString, true, new HashFilter(hash, new Base64Encoder(new StringSink(digest))));

    return digest;
}


// функция декодирования из base64
string Decoder(string aString) {
    string decoded;

    Base64Decoder decoder;
    decoder.Put((byte*)aString.data(), aString.size());
    decoder.MessageEnd();

    word64 size = decoder.MaxRetrievable();
    if (size && size <= SIZE_MAX)
    {
        decoded.resize(size);
        decoder.Get((byte*)&decoded[0], decoded.size());
    }

    return decoded;
}

// класс сервер
class Server // имя класса
{
private:
    // контейнер для хранения данных вида [ключ — значение]
    map <string, string> db;
    map <string, string> db_N;
public:
    //функция генерации случайного числа N
    string generator_N(string login) {
        string hash_N;
        byte pcbScratch[BLOCKSIZE];

        // Создание криптографически стойкого генератора
        AutoSeededX917RNG<DES_EDE3> rng;
        string N_str;

        const auto found = db.find(login);
        //проверка на существование логина в базе db
        if (found != db.cend()) {
            cout << "Server: Генерация числа N..." << endl;
            rng.GenerateBlock(pcbScratch, BLOCKSIZE); //генерация случайного числа
            for (int i = 0; i < BLOCKSIZE; i++) {
                N_str += pcbScratch[i];
            }
            cout << "Server: Генерация прошла успешно. N = " << SHA256HashString(N_str) << endl;
            db_N[login] = N_str;
            return N_str;
        }
    }

    // функция регистрации
    int registration(string login, string password)
    {
        const auto found = db.find(login);
        if (found == db.cend()) {
            db[login] = SHA256HashString(password); // шифрование пароля с помощью sha256

            for (auto it = db.begin(); it != db.end(); ++it) {
                cout << "Server: Регистрация прошла. Данные в базе db: '" << (*it).first << "' : " << (*it).second << endl;
                return true;
            }
        }
        else {
            cout << "Server: Error. Пользователь уже зарегистрирован с таким логином." << endl;
            return false;
        }

    }
    // функция проверки аутентификации
    int auth(string login, string password) {
        const auto found = db.find(login);
        const auto found_N = db_N.find(login);
        string hash_N = SHA256HashString(db_N[login]);

        string new_pass_server = SHA256HashString(Decoder(hash_N) + Decoder(db[login]));
        cout << "Server: Новый пароль, сгенерированный Server: " << new_pass_server << endl;

        if (found != db.cend() and found_N != db_N.cend()) {
            if (Decoder(new_pass_server) != Decoder(password)) {
                cout << "Server: Неверный пароль!!!!!!" << endl;
                return false;
            }
            else {
                cout << "Server: Успешная аутентификация." << endl;
                return true;
            }
        }
        else {
            cout << "Server: Неверный логин = '" << login << "' " << endl;
            return false;
        }
    }
};

//Класс Пользователь
class User
{
private:
    string N;
public:
    //функция регистрации пользователя
    void regisration_user(Server& server, string login, string password) {

        string pass = SHA256HashString(password);
        cout << "User: Исходные данные. Логин = '" << login << "', пароль = " << pass << endl;

        cout << "User: Регистрация..." << endl;
        bool status_registration = server.registration(login, password);
        if (status_registration == true) {
            cout << "User: Успешная регистрация." << endl;
        }
        else {
            cout << "User: Ошибка при регистрации." << endl;
        }
    }
    
    //функция аутентификации пользователя
    void auth_user(Server& server, string login, string password) {
        string hash_pass = SHA256HashString(password);
        cout << "User: Аутентификация... Введенный пароль: " << hash_pass << endl;
        //генерация случайного числа N
        N = server.generator_N(login);

        string hash_N = SHA256HashString(N);

        cout << "User: Server передал случайное число N с помощью криптографически стойкого генератора = " << hash_N << endl;
        cout << endl;
        string pass = SHA256HashString(Decoder(hash_N) + Decoder(hash_pass));
        cout << "User: Новый пароль, сгенерированный User: " << pass << endl;

        bool status_auth = server.auth(login, pass);
        if (status_auth == true) {
            cout << "User: Успешная аутентификация" << endl;
        }
        else {
            cout << "User: Ошибка при аутентификации" << endl;
        }
    }
};


int main(int argc, char* argv[])
{
    setlocale(LC_ALL, "rus");
    Server objCHAPServer; // объявление класса Server
    User objCHAPUser; // объявление класса User

    // Корректные данные
    
    //objCHAPUser.regisration_user(objCHAPServer, "Boby", "qwerty123");
    //objCHAPUser.auth_user(objCHAPServer, "Boby", "qwerty123");

    //Некорректный пароль
    objCHAPUser.regisration_user(objCHAPServer, "Alice", "123");
    objCHAPUser.auth_user(objCHAPServer, "Alice", "qr1258963");
    
    
    
    system("pause");
    return 0;
}
