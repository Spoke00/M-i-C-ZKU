#include <iostream>
#include <string>
#ifdef _WIN32
#include <windows.h>
#endif

using namespace std;


const string ALPHABET_RU = "абвгдеёжзийклмнопрстуфхцчшщъыьэюяАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ0123456789 .,!?;:-";
const string ALPHABET_EN = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,!?;:-";

int getIndex(char c, const string& alphabet) {
    size_t pos = alphabet.find(c);
    return (pos == string::npos) ? -1 : static_cast<int>(pos);
}

string Encrypt(const string& text, int K, const string& alphabet) {
    string result = text;
    int N = alphabet.length();

    for (char& c : result) {
        int X = getIndex(c, alphabet);
        if (X != -1) {
            int Y = ((X + K) % N + N) % N;
            c = alphabet[Y];
        }
    }
    return result;
}

string Decrypt(const string& text, int K, const string& alphabet) {
    return Encrypt(text, -K, alphabet);
}


string chooseAlphabet() {
    int choice;
    cout << "\n Alphabet choice" << endl;
    cout << "1. Russian" << endl;
    cout << "2. English" << endl;
    cout << "3. Input Alphabet" << endl;
    cout << "Choice: ";
    cin >> choice;

    switch (choice) {
    case 1: return ALPHABET_RU;
    case 2: return ALPHABET_EN;
    case 3: {
        cin.ignore();
        string custom;
        cout << "Input your alphabet:";
        getline(cin, custom);
        return custom;
    }
    default:
        cout << "Error, using russian alphabet" << endl;
        return ALPHABET_RU;
    }
}


void runCLI(int argc, char* argv[]) {
    if (argc < 4) {
        cout << "Error! Format: program.exe <text> <e|d> <offset> [alphabet]" << endl;
        return;
    }

    string text = argv[1];
    string mode = argv[2];
    int K = stoi(argv[3]);
    string alphabet = (argc >= 5) ? argv[4] : ALPHABET_RU;

    string result;
    if (mode == "e" || mode == "E") {
        result = Encrypt(text, K, alphabet);
        cout << "Encrypted text: " << result << endl;
    }
    else if (mode == "d" || mode == "D") {
        result = Decrypt(text, K, alphabet);
        cout << "Decoded text: " << result << endl;
    }
    else {
        cout << "Error! The mode must be either 'e' or 'd'." << endl;
    }
}


void runInteractive() {
    string alphabet = chooseAlphabet();
    cout << "\nPower alphabet (N): " << alphabet.length() << endl;

    string text, encryptedText;
    int mode, K;

    while (true) {
        cout << "\n Menu" << endl;
        cout << "1. Encrypt the text" << endl;
        cout << "2. Decode the text" << endl;
        cout << "3. Decode the last encrypted text." << endl;
        cout << "4. Change alphabet" << endl;
        cout << "0. Exit" << endl;
        cout << "Choose an action: ";
        cin >> mode;

        if (mode == 0) {
            cout << "\nThe program has been completed. Goodbye!" << endl;
            break;
        }

        if (mode == 1) {
            cin.ignore();
            cout << "Enter the text to be encrypted.: ";
            getline(cin, text);

            cout << "Enter the offset (K): ";
            cin >> K;

            encryptedText = Encrypt(text, K, alphabet);
            cout << "\nThe original text:       " << text << endl;
            cout << " Encrypted text:  " << encryptedText << endl;
        }
        else if (mode == 2) {
            cin.ignore();
            cout << "Enter the text to be decrypted: ";
            getline(cin, text);

            cout << "Enter the offset (K): ";
            cin >> K;

            string decryptedText = Decrypt(text, K, alphabet);
            cout << "\nEncrypted text:   " << text << endl;
            cout << "Decoded text:  " << decryptedText << endl;
        }
        else if (mode == 3) {
            if (encryptedText.empty()) {
                cout << "\nError: You haven’t encrypted any texts yet!" << endl;
            }
            else {
                cout << "Enter the offset (K): ";
                cin >> K;

                string decryptedText = Decrypt(encryptedText, K, alphabet);
                cout << "\nEncrypted text:   " << encryptedText << endl;
                cout << "Decoded text:  " << decryptedText << endl;
            }
        }
        else if (mode == 4) {
            alphabet = chooseAlphabet();
            cout << "\nA new alphabet has been chosen. Power (N): " << alphabet.length() << endl;
            encryptedText.clear();
        }
        else {
            cout << "\nIncorrect choice! Please try again." << endl;
        }
    }
}

int main(int argc, char* argv[]) {
    #ifdef _WIN32
    SetConsoleCP(1251);
    SetConsoleOutputCP(1251);
    setlocale(LC_ALL, "Russian");
    #endif

    if (argc > 1) {
        runCLI(argc, argv);
    }
    else {
        runInteractive();
    }

    return 0;
}
