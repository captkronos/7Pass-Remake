7Pass-Remake
============

A remake of 7Pass for WinRT (Windows 8.1 and Windows Phone 8.1)

This fork "bolts-on" NFC functionality to 7Pass-Remake. It has not been integrated in a way that I would expect the final
solution to work but rather as a proof of concept.

The code allows different combinations of database name, key file name, key file contents to be store on the NFC Tag. The
current implementation does now allow the user to chose what is stored on the NFC Tag but rather all three elements are
stored.

User Instructions
Set up a database as usual including chosing the appropriate key file. You will then notice a write tag button. Click on it
and then tap your NFC tag and ensure a write message is displayed. Once you have completed that process, whenever you are at
the database list page tapping the NFC Tag will automatically chose the corresponding database, embed the key file's contents
and then you will be prompted for the database password.

You will need to make sure that you chose an NFC Tag with sufficient capacity. The required capacity will depend predominantly
on two factors: the length of the database name and the length of the key file's contents. To be safe Type 3 and Type 4 will
work such as NTAG215, NTAG216, Mifare 1k, Desfire 4k, Topaz 512.

Warning
Whilst there is some obfuscation of the contents of the NFC Tag you should not assume the contents is encrypted. If you 
lose the NFC tag, you should assume the key file has been compromised and change the key file of your database.
