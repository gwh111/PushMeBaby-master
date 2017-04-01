//3des-ecb加密方式
	bool Encode3DESCpp(const std::string& strKey, const std::string& strPlaintext, std::string& strCiphertext);
	bool Decode3DESCpp(const std::string& strKey, const std::string& strPlaintext, std::string& strCiphertext);

	
	
#define LEN_OF_KEY_DES 24

bool Encode3DESCpp(const std::string& strKey, const std::string& strPlaintext, std::string& strCiphertext)
{
	bool bSuccess= false;
	do 
	{
		if (strKey.size() > LEN_OF_KEY_DES)
			break;

		unsigned char key[LEN_OF_KEY_DES]={0};
		memcpy_s(key,LEN_OF_KEY_DES,strKey.c_str(),strKey.size());

		unsigned char block_key[9]={0}; 
		DES_key_schedule ks1,ks2,ks3;
		memset(block_key, 0, sizeof(block_key)); 
		memcpy(block_key, key + 0, 8); 
		DES_set_key_unchecked((const_DES_cblock*)block_key, &ks1); 
		memcpy(block_key, key + 8, 8); 
		DES_set_key_unchecked((const_DES_cblock*)block_key, &ks2); 
		memcpy(block_key, key + 16, 8); 
		DES_set_key_unchecked((const_DES_cblock*)block_key, &ks3);

		int data_len = strPlaintext.size();
		int data_rest = data_len % 8;
		int len = data_len +( 8 - data_rest);
		char ch = 8 - data_rest;

		//PKCS5
		char* src = (char*)malloc(len);
		char* dst = (char*)malloc(len);
		memset(src, 0, len); 
		memcpy(src, strPlaintext.c_str(), data_len); 
		memset(src + data_len, ch, 8 - data_rest);
		memset(dst,0,len);

		for (int i=0; i<len; i+=8)
		{
			DES_ecb3_encrypt( (C_Block*)(src + i),  (C_Block*)(dst + i), &ks1, &ks2, &ks3, DES_ENCRYPT);
		}
		strCiphertext.assign(dst,len);
	} while (0);
	return bSuccess;
}

bool Decode3DESCpp(const std::string& strKey, const std::string& strPlaintext, std::string& strCiphertext)
{
	bool bSuccess= false;
	do 
	{
		if (strKey.size() > LEN_OF_KEY_DES)
			break;

		unsigned char key[LEN_OF_KEY_DES]={0};
		memcpy_s(key,LEN_OF_KEY_DES,strKey.c_str(),strKey.size());

		unsigned char block_key[9]={0}; 
		DES_key_schedule ks1,ks2,ks3;
		memset(block_key, 0, sizeof(block_key)); 
		memcpy(block_key, key + 0, 8); 
		DES_set_key_unchecked((const_DES_cblock*)block_key, &ks1); 
		memcpy(block_key, key + 8, 8); 
		DES_set_key_unchecked((const_DES_cblock*)block_key, &ks2); 
		memcpy(block_key, key + 16, 8); 
		DES_set_key_unchecked((const_DES_cblock*)block_key, &ks3);

		//密文的大小必须是8的倍树
		int len = strPlaintext.size();
		if (len%8 != 0)
			break;

		char* src = (char*)malloc(len);
		char* dst = (char*)malloc(len);
		memset(src,0,len); 
		memset(dst,0,len);
		memcpy(src, strPlaintext.c_str(), strPlaintext.size());

		for (int i=0; i<len; i+=8)
		{
			
			DES_ecb3_encrypt((C_Block *)(src + i), (C_Block *)(dst + i), &ks1, &ks2, &ks3, DES_DECRYPT);
		}
		//PKCS5:获取最后一个字节来处理多余的字符
		char ch1 = *(dst+len-1);
		strCiphertext.assign(dst,len-ch1);
	} while (0);
	return bSuccess;
}
