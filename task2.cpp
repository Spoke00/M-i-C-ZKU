#include <iostream>
#include <string>
#include <fstream>
#include <algorithm>
#include <random>
#ifdef _WIN32
#include <windows.h>
#endif

using namespace std;

const string ALPHABET = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя0123456789 .,!?;:-";
const string KEY_FILE = "key.txt";

string generateKey(const string& alphabet) {
    string key = alphabet;
    random_device rd;
    mt19937 g(rd());
    shuffle(key.begin(), key.end(), g);
    return key;
}

string loadOrGenerateKey(const string& alphabet) {
    ifstream fin(KEY_FILE);
    if (fin.is_open()) {
        string key;
        getline(fin, key);
        fin.close();

        if (key.length() == alphabet.length()) {
            cout << "Substitution table loaded from file " << KEY_FILE << endl;
            return key;
        }
    }

    cout << "File not found. Generating a new substitution table...\n";
    string key = generateKey(alphabet);

    ofstream fout(KEY_FILE);
    if (fout.is_open()) {
        fout << key;
        fout.close();
        cout << "Table saved to " << KEY_FILE << endl;
    }
    else {
        cerr << "File write error!\n";
    }

    return key;
}

string Encrypt(const string& text, const string& key, const string& alphabet) {
    string result = text;
    for (char& c : result) {
        size_t idx = alphabet.find(c);
        if (idx != string::npos) {
            c = key[idx];
        }
    }
    return result;
}

string Decrypt(const string& text, const string& key, const string& alphabet) {
    string result = text;
    for (char& c : result) {
        size_t idx = key.find(c);
        if (idx != string::npos) {
            c = alphabet[idx];
        }
    }
    return result;
}

void runCLI(int argc, char* argv[]) {
    if (argc < 3) {
        cout << "Error! Format: task2.exe <text> <e|d> [alphabet]" << endl;
        cout << "Example: task2.exe \"hello\" e" << endl;
        return;
    }

    string text = argv[1];
    string mode = argv[2];
    string alphabet = (argc >= 4) ? argv[3] : ALPHABET;

    string key = loadOrGenerateKey(alphabet);

    string result;
    if (mode == "e" || mode == "E") {
        result = Encrypt(text, key, alphabet);
        cout << "Encrypted text: " << result << endl;
    }
    else if (mode == "d" || mode == "D") {
        result = Decrypt(text, key, alphabet);
        cout << "Decrypted text: " << result << endl;
    }
    else {
        cout << "Error! Mode must be 'e' or 'd'" << endl;
    }
}

void runInteractive() {
    string key = loadOrGenerateKey(ALPHABET);

    cout << "\n=== SUBSTITUTION TABLE ===" << endl;
    cout << "Alphabet:      " << ALPHABET << endl;
    cout << "Substitution:  " << key << endl;
    cout << endl;

    string text, encryptedText;
    int mode;

    while (true) {
        cout << "--- MENU ---" << endl;
        cout << "1. Encrypt text" << endl;
        cout << "2. Decrypt text" << endl;
        cout << "3. Decrypt the last encrypted text" << endl;
        cout << "4. Show substitution table" << endl;
        cout << "5. Generate a new substitution table" << endl;
        cout << "0. Exit" << endl;
        cout << "Choose an action: ";
        cin >> mode;

        if (mode == 0) {
            cout << "\nProgram terminated. Goodbye!" << endl;
            break;
        }

        if (mode == 1) {
            cin.ignore();
            cout << "Enter text to encrypt: ";
            getline(cin, text);

            encryptedText = Encrypt(text, key, ALPHABET);
            cout << "\nOriginal text:      " << text << endl;
            cout << "Encrypted text:     " << encryptedText << endl;
        }
        else if (mode == 2) {
            cin.ignore();
            cout << "Enter text to decrypt: ";
            getline(cin, text);

            string decryptedText = Decrypt(text, key, ALPHABET);
            cout << "\nEncrypted text:     " << text << endl;
            cout << "Decrypted text:     " << decryptedText << endl;
        }
        else if (mode == 3) {
            if (encryptedText.empty()) {
                cout << "\nError: You haven't encrypted any text yet!" << endl;
            }
            else {
                string decryptedText = Decrypt(encryptedText, key, ALPHABET);
                cout << "\nEncrypted text:     " << encryptedText << endl;
                cout << "Decrypted text:     " << decryptedText << endl;
            }
        }
        else if (mode == 4) {
            cout << "\n=== SUBSTITUTION TABLE ===" << endl;
            cout << "Alphabet:      " << ALPHABET << endl;
            cout << "Substitution:  " << key << endl;
        }
        else if (mode == 5) {
            cout << "\nGenerating a new substitution table..." << endl;
            key = generateKey(ALPHABET);

            ofstream fout(KEY_FILE);
            if (fout.is_open()) {
                fout << key;
                fout.close();
                cout << "New table saved to " << KEY_FILE << endl;
            }
            encryptedText.clear();
        }
        else {
            cout << "\nInvalid choice! Try again." << endl;
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