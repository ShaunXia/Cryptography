#include <iostream>
#include <string>
#include <iomanip>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
using namespace std;
class RC4
{
public:
	void GenKey();
	void EnCode();
	void DeCode();
	int GetNum(char c);
	void init();
private:
	string key;
	int *engineState;
	string message;
	int message_length;
	int key_length;
	int bit;
	int *reint;
};

void RC4::init()
{
	reint=new int[256];
	bit=256;
	engineState=new int[bit];
}
void RC4::GenKey()
{	
	cout<<"Input Your KEY: ";
	cin>>key;
	key_length=key.length();
	for(int i=0;i<bit;++i)
	{
		engineState[i]=i;
	}
	int j=0,tp;
	for(int i=0;i<bit;++i)
	{
		j=(j+engineState[i]+key[i%key_length])%bit;
		tp=engineState[i];
		engineState[i]=engineState[j];
		engineState[j]=tp;
	}

}
void RC4::EnCode()
{

	cout<<"Input Your MESSAGE: ";
	cin>>message;
	message_length=message.length();

	int i=0,j=0,tp,t;
	char tps[256];
	string restr="";
	cout<<"CIPHERTEXT is : ";
	for(int k=0;k<message_length;++k)
	{
		i=(i+1)%bit;
		j=(j+engineState[i])%bit;
		swap(engineState[i],engineState[j]);
		t=(engineState[i]+engineState[j])%bit;
		int re=engineState[t]^message[k];
		sprintf(tps,"%02X",re);
		string st(tps);
		restr+=st;
		reint[k]=re;
		cout<<setfill('0')<<setw(2)<<uppercase<<hex<<reint[k];
	}
	cout<<endl;

}


int RC4::GetNum(char c)
{
	if(isalpha(c))
	{
		if(isupper(c))
			return (c-'A')+10;
		else
			return c-'a'+10;
	}
	return c-'0';
}

void RC4::DeCode()
{
	cout<<"Input Your CIPHERTEXT: ";
	//int tp[];
	string cip,str_2;
	cin>>cip;
	int usrint[100];

	for(int i=0;i<cip.length();i+=2)
	{
		usrint[i/2]=GetNum(cip[i])*16+GetNum(cip[i+1]);
	}

	int i=0,j=0,tp,t;
	char res[100];
	cout<<"Message is : ";
	for(int k=0;k<cip.length()/2;++k)
	{
		i=(i+1)%bit;
		j=(j+engineState[i])%bit;
		swap(engineState[i],engineState[j]);
		t=(engineState[i]+engineState[j])%bit;
		char re=engineState[t]^usrint[k];
		cout<<re;
	}
	cout<<endl;
}

int main()
{
	int tp;
	RC4 rc;
	cout<<"==========Encrypt============="<<endl;
	rc.init();
	rc.GenKey();
	rc.EnCode();
	cout<<endl<<"==========Decrypt============="<<endl;
	rc.GenKey();
	rc.DeCode();
	system("pause");
	return 0;

}