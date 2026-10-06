using SensitiveContent.Classes;

FileHandler fileHandler = new();
DoubleRatchet doubleRatchet = new(new AesHmac(), new AesHmac());

void ImportRecipientPK(bool init)
{
    bool isKeySet;

    if (!init)
    {
        Console.WriteLine("\nSend the following to the instance that should send messages first:");
        Console.WriteLine($"{doubleRatchet.PrintPublicKey()}");

        FileHandler.ReadKey();
        return;
    }

    do
    {
        Console.Clear();
        Console.Write("Enter the received public key: ");

        try
        {
            doubleRatchet.Init(new Ecdh(Console.ReadLine()!));
            isKeySet = true;
        }
        catch
        {
            isKeySet = false;
        }

        if (isKeySet)
            Console.WriteLine("Key imported successfully.");
        else
            Console.WriteLine("Malformed key, try again.");
    } while (!isKeySet);

    FileHandler.ReadKey();
}

void AesCrypt(bool isEncrypt, bool isFile)
{
    if (!isFile)
    {
        Console.Write($"{(isEncrypt ? "Message" : "Blob")}: ");
        string data = Console.ReadLine()!;

        if (isEncrypt)
            Console.WriteLine($"{"Blob"}: {FileHandler.ToBase64(doubleRatchet.EncryptString(data))}");
        else
            Console.WriteLine($"{"Message"}: {doubleRatchet.DecryptString(FileHandler.FromBase64(data))}");
    }
    else
    {
        Console.Write("Input path: ");
        byte[] input = File.ReadAllBytes(Console.ReadLine()!);

        Console.Write("Output path: ");
        string outputPath = Console.ReadLine()!;

        if (isEncrypt)
        {
            fileHandler.WriteRaw(outputPath, doubleRatchet.Encrypt(input));
            Console.WriteLine("Encrypted file written successfully");
        }
        else
        {
            try
            {
                fileHandler.WriteRaw(outputPath, doubleRatchet.Decrypt(input));
                Console.WriteLine("Decrypted file written successfully");
            }
            catch (Exception)
            {
                Console.WriteLine("Something bad occurred");
            }
        }
    }

    FileHandler.ReadKey();
}

void Menu()
{
    int option;

    do
    {
        Console.Clear();
        Console.WriteLine("1. Send encrypted text");
        Console.WriteLine("2. Receive decrypted text");
        Console.WriteLine("3. Send encrypted file");
        Console.WriteLine("4. Receive decrypted file");
        Console.WriteLine("0. Exit");

        option = FileHandler.GetInt("Option");

        switch (option)
        {
            case 1:
                AesCrypt(isEncrypt: true, isFile: false);
                break;
            case 2:
                AesCrypt(isEncrypt: false, isFile: false);
                break;
            case 3:
                AesCrypt(isEncrypt: true, isFile: true);
                break;
            case 4:
                AesCrypt(isEncrypt: false, isFile: true);
                break;
            default:
                break;
        }
    } while (option != 0);
}

Console.Write("Is this instance the one that should send messages first? [yN] ");
ImportRecipientPK(Console.ReadKey().KeyChar == 'y');

Menu();