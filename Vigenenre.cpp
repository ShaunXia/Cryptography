#include <iostream>
#include <string>
using namespace std;
char table[26][26];
void GenTable()
{
	for(int i=0;i<26;++i)
	{
		for(int j=0;j<26;++j)
			table[i][j]='A'+(i+j)%26;		
	}
	// for(int i=0;i<26;++i)
	// {
	// 	for(int j=0;j<26;++j)
	// 		cout<<table[i][j]<<" ";
	// 	cout<<endl;		
	// }
}
int main()
{
	GenTable();
	string key,message,ciphertext;
	int message_length,key_length,message_num,key_num,tp,ciphertext_length;
	int cip_num,cip_key_num;
	// key="deceptive";
	// message="wearediscoveredsaveyourself";
	cout<<"-------------Encode here-------------"<<endl;
	cout<<"Enter your key: ";
	cin>>key;
	cout<<"Enter your Message: ";
	cin>>message;
	message_length=message.length();
	key_length=key.length();
	tp=0;
	cout<<"Your ciphertext is: ";
	ciphertext="";
	for(int i=0;i<message_length;++i)
	{
		if(i>key_length)
			tp=i%key_length;
		else
			tp=i;

		message_num=message[i]-'a';
		key_num=key[tp]-'a';
	 	ciphertext=ciphertext+table[message_num][key_num];
	}
	cout<<ciphertext;
	cout<<endl;
	cout<<"-------------Decode here-------------"<<endl;
	cout<<"Enter your key: ";
	cin>>key;
	cout<<"Enter your ciphertext: ";
	cin>>ciphertext;
	tp=0;
	char temp;
	ciphertext_length=ciphertext.length();
	message="";
	for(int i=0;i<ciphertext_length;++i)
	{

		if(i>key_length)
			tp=i%key_length;
		else
			tp=i;
		cip_key_num=key[tp]-'a';
		for (int j = 0; j < 26; ++j)
		{
			if(table[cip_key_num][j]==ciphertext[i])
				{
					cip_num=j;
					temp='a'+j;
					message+=temp;
					break;
				}
		}
	}
	cout<<"Your Message is: ";
	cout<<message<<endl;
	cin>>tp;
	return 0;
}