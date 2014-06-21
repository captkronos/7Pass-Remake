//Based on NdefDemo

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Linq;
using System.Text;
using System.Windows;
using System.IO;
using Windows.Storage;
using Windows.Storage.Streams;
using System.Threading.Tasks;
using Windows.Networking.Proximity;
using NdefLibrary.Ndef;
using NdefLibraryWp.Ndef;

using Windows.Security.Cryptography;
using Windows.Security.Cryptography.DataProtection;



namespace KeePassNFC
{
    class NFC
    {
        private ProximityDevice _device;
        private long _subscriptionIdNdef;
        private long _subscriptionWTag;
        private long _publishingMessageId;
        private byte[] subscribeMsg;
        private Action<int> subscribeCallback=null;
        private Action<int> subscripeWTagCallback = null;
        private Action<int> publishCallback = null;
        private long _msgLength;
        private int _tagSize;
        private byte[] Obfuscation = new byte[] { 32,71,123,213,162,200,41,163,192,62,9,61,39,54,27,95,66,24,105,184,24,250,2,82,152,193,210,90,115 }; //random stuff

        //A little bit of obfuscation
        private void EncryptDecrypt(byte[] data, byte[] key)
        // "proper" crypto has too much of a size overhead but since the key will have to be embedded somewhere in the device it wouldn't be that secure anyway
        {
            for (int i = 0; i < data.Length; i++)
            {
                data[i] = (byte)(data[i] ^ key[i % key.Length]);
            }
        }
        private async void Encrypt(byte[] data)
        {
            //byte[] encryptedEmergencyInfoByteArray = ProtectedData.Protect(data, null);
            String strMsg = "This is a message to be protected.";
            String strDescriptor = "LOCAL=user";
            BinaryStringEncoding encoding = BinaryStringEncoding.Utf8;

            // Create a DataProtectionProvider object for the specified descriptor.
            DataProtectionProvider Provider = new DataProtectionProvider(strDescriptor);

            // Encode the plaintext input message to a buffer.
            encoding = BinaryStringEncoding.Utf8;
            IBuffer buffMsg = CryptographicBuffer.ConvertStringToBinary(strMsg, encoding);

            // Encrypt the message.
            IBuffer buffProtected = await Provider.ProtectAsync(buffMsg);


        }
        private async void ReadBytesFromFile(string filename, IBuffer buffer)
        {
            StorageFolder documentsFolder = KnownFolders.DocumentsLibrary;
            StorageFile file = await documentsFolder.GetFileAsync(filename);
            if (file != null)
            {
                try
                {
                    buffer = await FileIO.ReadBufferAsync(file);
                    //using (DataReader dataReader = DataReader.FromBuffer(buffer))
                    //{
                    //    string fileContent = dataReader.ReadBuffer(buffer.Length);
                    //    //rootPage.NotifyUser(String.Format("The following {0} bytes of text were read from '{1}':{2}{3}", buffer.Length, file.Name, Environment.NewLine, fileContent), NotifyType.StatusMessage);
                    //}
                }
                catch (FileNotFoundException)
                {
                    //rootPage.NotifyUserFileNotExist();
                }
            }
            else
            {
                //rootPage.NotifyUserFileNotExist();
            }
        }

        public int SubscribeAsync(Action<int> callback)
        {
            if (_device == null)
                _device = ProximityDevice.GetDefault();
            if (_device == null)
                return -2; //nfc does not exist or not switched on
            subscribeCallback=callback;
            // Only subscribe for messages if no NDEF subscription is already active
            if (_subscriptionIdNdef != 0) return -1;
            // Ask the proximity device to inform us about any kind of NDEF message received from
            // another device or tag.
            // Store the subscription ID so that we can cancel it later.
            _subscriptionIdNdef = _device.SubscribeForMessage("NDEF", MessageReceivedHandler);
            return 0;
        }
        public void stopSubscribing()
        {
            if (_subscriptionIdNdef != 0 && _device != null)
            {
                // Ask the proximity device to stop subscribing for NDEF messages
                _device.StopSubscribingForMessage(_subscriptionIdNdef);
                _subscriptionIdNdef = 0;
            }

        }
        public int SubscribeForWritableTagAsync(Action<int> callback)
        {
            _tagSize = -1;
            if (_device == null)
                _device = ProximityDevice.GetDefault();
            if (_device == null)
                return -2; //nfc does not exist or not switched on
            subscripeWTagCallback = callback; //actually we don't use this callback!
            // Only subscribe for messages if no NDEF subscription is already active
            if (_subscriptionWTag != 0) return -1;
            // Ask the proximity device to inform us about any kind of NDEF message received from
            // another device or tag.
            // Store the subscription ID so that we can cancel it later.
            _subscriptionWTag = _device.SubscribeForMessage("WriteableTag", WriteableTagReceivedHandler);
            return 0;
        }
        public void stopSubscribingForWritableTag()
        {
            if (_subscriptionWTag != 0 && _device != null)
            {
                // Ask the proximity device to stop subscribing for NDEF messages
                _device.StopSubscribingForMessage(_subscriptionWTag);
                _subscriptionWTag = 0;
            }

        }
        public byte[] subscribeReceivedMsg()
        {
            return subscribeMsg;
        }

        public int PublishAsync(Action<int> callback, byte[] payload)
            //callback recieves:
            // if success - the size of the tag written to
            // if tag too small - the size of the tag * -1
            // if some other error - 0
        {
            if (_device == null)
                _device = ProximityDevice.GetDefault();
            if (_device == null)
                return -2; //nfc does not exist or not switched on
            publishCallback = callback;
            SubscribeForWritableTagAsync(null);
            NdefRecord record = new NdefRecord();
            record.TypeNameFormat = NdefRecord.TypeNameFormatType.Unknown;
            record.Payload = payload;
            // Publish the record using the proximity device
            PublishRecord(record, true);
            return 0;
        }
        static byte[] GetBytes(string str)
        {
            byte[] bytes = new byte[str.Length * sizeof(char)];
            System.Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);
            return bytes;
        }

        public byte[] makeKeePassNFCRecord(string dbName, string dbId, string keyFileFilename, byte[] keyFileContents, byte[] obfuscation)
        {
            int formatOverhead=0,p=0;
            //sanity check - note that the following max figures are much bigger than anything that could be stored on today's tags but have been set to provide for future expansion!
            if (dbName.Length > 100 || dbId.Length > 100 || keyFileFilename.Length > 100 || keyFileContents.Length > 5000)
                return null;
            if (obfuscation == null)
                obfuscation = Obfuscation;
            if (dbName.Length != 0)
                formatOverhead+=3;
            if (dbId.Length != 0)
                formatOverhead+=3;
            if (keyFileFilename.Length != 0)
                formatOverhead+=3;
            if (keyFileContents.Length!=0)
                formatOverhead+=3;
            byte[] bytes = new byte[(dbName.Length + dbId.Length + keyFileFilename.Length) * sizeof(char) + keyFileContents.Length + formatOverhead];
            if (dbName.Length != 0)
            {
                bytes[p++]=(byte)'<';
                bytes[p++]=(byte)'d';
                System.Buffer.BlockCopy(dbName.ToCharArray(), 0, bytes, p, dbName.Length * sizeof(char));
                p += dbName.Length * sizeof(char);
                bytes[p++]=(byte)'>';
            };
            if (dbId.Length != 0)
            {
                bytes[p++] = (byte)'<';
                bytes[p++] = (byte)'i';
                System.Buffer.BlockCopy(dbId.ToCharArray(), 0, bytes, p, dbId.Length * sizeof(char));
                p += dbId.Length * sizeof(char);
                bytes[p++] = (byte)'>';
            };
            if (keyFileFilename.Length != 0)
            {
                bytes[p++]=(byte)'<';
                bytes[p++]=(byte)'f';
                System.Buffer.BlockCopy(keyFileFilename.ToCharArray(), 0, bytes, p, keyFileFilename.Length * sizeof(char));
                p += keyFileFilename.Length * sizeof(char);
                bytes[p++]=(byte)'>';
            };
            if (keyFileContents.Length!=0)
            {
                bytes[p++]=(byte)'<';
                bytes[p++]=(byte)'k';
                System.Buffer.BlockCopy(keyFileContents,0,bytes,p,keyFileContents.Length);
                p+=keyFileContents.Length;
                bytes[p++]=(byte)'>';
            };
            //Encrypt(bytes);
            if (obfuscation != null)
                EncryptDecrypt(bytes, obfuscation);
            return bytes;
        }
        public int deconstructKeePassNFCRecord(byte[] keePassNFCRecord, out string dbFilename, out string dbId, out string keyFileFilename, out byte[] keyFileContents, byte[] obfuscation)
        {
            int p = 0, s=0, ret=0;
            if (obfuscation == null)
                obfuscation = Obfuscation;
            dbFilename = "";
            dbId = "";
            keyFileFilename = "";
            keyFileContents = null;
            if (obfuscation != null)
                EncryptDecrypt(keePassNFCRecord, obfuscation);
            while (p<keePassNFCRecord.Length && ret==0 && p<7000) // the 7000 is just to provide some theoretical upper bound
            {
                 if (keePassNFCRecord[p++] == (byte)'<')
                    switch (keePassNFCRecord[p++])
                    {
                        case (byte)'d':
                            s = Array.IndexOf(keePassNFCRecord, (byte) '>', p);
                            if (s > p && s-p < 1000)
                            {
                                dbFilename = System.Text.Encoding.Unicode.GetString(keePassNFCRecord, p, s - p);
                                p = s + 1;
                            }
                            else
                                ret = -1;
                            break;
                        case (byte)'i':
                            s = Array.IndexOf(keePassNFCRecord, (byte)'>', p);
                            if (s > p && s - p < 1000)
                            {
                                dbId = System.Text.Encoding.Unicode.GetString(keePassNFCRecord, p, s - p);
                                p = s + 1;
                            }
                            else
                                ret = -2;
                            break;
                        case (byte)'f':
                            s = Array.IndexOf(keePassNFCRecord, (byte) '>', p);
                            if (s > p && s - p < 1000)
                            {
                                keyFileFilename = System.Text.Encoding.Unicode.GetString(keePassNFCRecord, p, s - p);
                                p = s + 1;
                            }
                            else
                                ret = -3;
                            break;
                        case (byte)'k':
                            s = keePassNFCRecord.Length - 1;
                            if (s > p && keePassNFCRecord[s] == (byte)'>' && s - p < 5000)
                            {
                                keyFileContents = new byte[s - p];
                                System.Buffer.BlockCopy(keePassNFCRecord,p,keyFileContents,0, s-p);
                                p = keePassNFCRecord.Length;
                            }
                            else
                                ret = -4;
                            break;
                        default:
                            ret = -5;
                            break;
                    }
                else
                {
                    ret = -6;
                }
            }
            return ret;
        }
        private void PublishRecord(NdefRecord record, bool writeToTag) 
        // writeToTag will always be True but para kept in for now
        {
            // Make sure we're not already publishing another message
            StopPublishingMessage();
            // Wrap the NDEF record into an NDEF message
            var message = new NdefMessage { record };
            // Convert the NDEF message to a byte array
            var msgArray = message.ToByteArray();
            _msgLength = msgArray.Length;
            // Publish the NDEF message to a tag or to another device, depending on the writeToTag parameter
            // Save the publication ID so that we can cancel publication later
            _publishingMessageId = _device.PublishBinaryMessage((writeToTag ? "NDEF:WriteTag" : "NDEF"), msgArray.AsBuffer(), MessageWrittenHandler);
        }
        
        private async void MessageWrittenHandler(ProximityDevice sender, long messageid)
        {
            int response;
            // Stop publishing the message
            StopPublishingMessage();
            if (publishCallback != null)
                if (_tagSize < _msgLength)
                    response = -1 * _tagSize; // actually WriteableTagReceivedHandler should have already sent this response back
                else
                    response = _tagSize;
            else
                response = 0;
            await Windows.ApplicationModel.Core.CoreApplication.MainView.CoreWindow.Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Normal, () =>
            { publishCallback(response); });
        }

        private async void  WriteableTagReceivedHandler(ProximityDevice sender, ProximityMessage message)
        {
            var tagSize = BitConverter.ToInt32(message.Data.ToArray(), 0);
            _tagSize = tagSize;
            if (publishCallback != null && _tagSize < _msgLength)
            {
                StopPublishingMessage();
                stopSubscribingForWritableTag();
                await Windows.ApplicationModel.Core.CoreApplication.MainView.CoreWindow.Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Normal, () =>
                { publishCallback(-1 * _tagSize); });
            }
        }
        public void StopPublishingMessage()
        {
            if (_publishingMessageId != 0 && _device != null)
            {
                // Stop publishing the message
                _device.StopPublishingMessage(_publishingMessageId);
                _publishingMessageId = 0;
            }
        }
        private async void MessageReceivedHandler(ProximityDevice sender, ProximityMessage message)
        {
            // Get the raw NDEF message data as byte array
            var rawMsg = message.Data.ToArray();
            // Let the NDEF library parse the NDEF message out of the raw byte array
            var ndefMessage = NdefMessage.FromByteArray(rawMsg);

            // Loop over all records contained in the NDEF message - currently only one record but keep it for future proofing!
            foreach (NdefRecord record in ndefMessage)
            {
                 subscribeMsg = new byte[record.Payload.Length];
                if (record.TypeNameFormat==NdefRecord.TypeNameFormatType.Unknown)
                {
                    record.Payload.CopyTo(subscribeMsg, 0);
                     if (subscribeCallback != null)
                        await Windows.ApplicationModel.Core.CoreApplication.MainView.CoreWindow.Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Normal, () => { subscribeCallback(0); });
                }
                else
                {
                    // Other types, not handled
                    if (subscribeCallback != null)
                        await Windows.ApplicationModel.Core.CoreApplication.MainView.CoreWindow.Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Normal, () => { subscribeCallback(-1); });
                }
            }
        }

    }
}
