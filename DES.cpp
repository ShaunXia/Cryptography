#include <iostream>
using namespace std;
class Des
{
public:
	Des();
	~Des();
	void init();
	void KeyToBin();
    void GetFinKey();
    void MsgToBin();
    void GetFinMsg(int num);
    void FindFromS();
    void GetNext();
    void Encryption();
    void FirstDo_En();
    
    void Decryption();
    void De_init();
    void CipToBin();
    void GetAllKey_de();
private:
	string key;
	int keybin[64];
    int key_pc_1[56];
    int key_pc_2[48];
	string message;
	int msgbin[64];
	int C[16][28];
	int D[16][28];
    int L[32];
    int R[32];
    int ER[48];
    int msg_ip[64];
    int A[48];
    int B[48];
    int PB[32];
    int nextR[32];
    int FINAL[64];
    int allkey[16][48];
    string ciphertext;
    int cipherBin[64];
    
    //////////////////////////////////
	const static int PC_1[];
	const static int PC_2[];
	const static int LeftMove[];
	const static int IP[];
	const static int E[];
	const static int S_Box[8][64];
	const static int IP_1[];
    const static int P[];
    //////////////////////////////////
};

const int Des::PC_1[]= { 57, 49, 41, 33, 25, 17, 9, 1, 58,
      50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
      63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45,
      37, 29, 21, 13, 5, 28, 20, 12, 4 }; 
const int Des::PC_2[] = { 14, 17, 11, 24, 1, 5, 3, 28, 15,
      6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37,
      47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36,
      29, 32 }; 

const int Des::LeftMove[] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2,
      2, 2, 2, 2, 1 }; 

const int Des::IP[] = { 58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48,
      40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19,
      11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7 }; 
const int Des::E[] = { 32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8,
      9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21,
      20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1 }; 

const int Des::S_Box[8][64] =                                    			
{ { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 ,
 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 ,
 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 ,
 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 }, // 表4：S_Box[1]
{ 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 ,
 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 ,
 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 ,
 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9} ,  // 表5：S_Box[2]
{ 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 ,
 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 ,
 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 ,
 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } , // 表6：S_Box[3]
{ 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 ,
 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 ,
 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 ,
 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } , // 表7：S_Box[4]
{ 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 ,
 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 ,
 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 ,
 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } , // 表8：S_Box[5]
{ 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 ,
 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 ,
 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 ,
 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } , // 表9：S_Box[6]
{ 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 ,
 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 ,
 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 ,
 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } , // 表10：S_Box[7]
{ 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 ,
 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 ,
 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 ,
 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 }};  // 表11：S_Box[8]


const int Des::P[] = { 16, 7, 20, 21, 29, 12, 28, 17, 1,
    15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22,
    11, 4, 25 }; //表12：32


const int Des::IP_1[] = { 40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45,
      13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19,
      59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25 }; // 表2：64
Des::Des()
{
    init();
}
Des::~Des()
{
	
}
void Des::KeyToBin()
{
	int tp=0;
	for (int i = 0; i <8; ++i)
	{
		tp=key[i];
		for (int j = 7; j >=0; --j)
		{
			keybin[i*8+j]=tp%2;
            tp/=2;
		}
	}

}
void Des::init()
{
    key="12345678";
    message="12345678";
    ciphertext="04FC1AD4078C4BE0";
    
}
void Des::GetFinKey()
{
    for (int num = 0; num < 16; ++num)
    {
    int tpC[28];
    int tpD[28];
    for (int i=0;i<28; ++i) {
        tpC[i]=C[0][i];
        tpD[i]=D[0][i];
    }
    for (int i=0; i<28; ++i)
    {
        C[0][i]=tpC[(i+LeftMove[num])%28];
        D[0][i]=tpD[(i+LeftMove[num])%28];
    }
    
    //LeftMove
    int tpLM[56];
    for (int i=0; i<28; ++i) {
        tpLM[i]=C[0][i];
        tpLM[i+28]=D[0][i];
    }
    
    for (int i=0; i<48; ++i) {
        key_pc_2[i]=tpLM[PC_2[i]-1];
        allkey[num][i]=key_pc_2[i];
    }
    }    
}
void Des::MsgToBin()
{
    int tp=0;
	for (int i = 0; i <8; ++i)
	{
		tp=message[i];
		for (int j = 7; j >=0; --j)
		{
			msgbin[i*8+j]=tp%2;
            tp/=2;
		}
	}
    
}

void Des::FirstDo_En()
{
    int i=0;
    for (i=0; i<64; ++i) {
        msg_ip[i]=msgbin[IP[i]-1];
    }
    //IP Transform
    
    for (i=0; i<32; ++i) {
        L[i]=msg_ip[i];
        R[i]=msg_ip[i+32];
        
    }
    //GET L R
    
    for (int i=0; i<56;++i) {
        key_pc_1[i]=keybin[PC_1[i]-1];
    }
    //PC_1
    
    
    for (i=0; i<28; ++i) {
        C[0][i]=key_pc_1[i];
        D[0][i]=key_pc_1[i+28];
    }
    //GET C & D
}

void Des::GetFinMsg(int num)
{
    int i=0;
    for (i=0; i<48; ++i) {
        ER[i]=R[E[i]-1];
      //  cout<<ER[i];
    }
    //GET ER[]
    cout<<endl<<"------A[]-------"<<endl;
    for (i=0; i<48; ++i) {
        A[i]=ER[i]^allkey[num][i];
        if (i%6==0&&i!=0) {
            cout<<endl;
        }
        cout<<A[i];
    }
    //Get A[]
}
void Des::FindFromS()
{
    int row,col,tmp;
    cout<<endl;
            cout<<endl<<"SELECT FORM S-BOX"<<endl;
    for (int i=0; i<8; ++i)
    {
        row=A[i*6+0]*2+A[i*6+5];
        col=A[i*6+1]*8+A[i*6+2]*4+A[i*6+3]*2+A[i*6+4];
        tmp=S_Box[i][row*16+col];
        cout<<row<<" "<<col<<endl;
      //  cout<<tmp<<endl;
        for (int j = 3; j >=0; --j)
        {
            B[i*4+j]=tmp%2;
            tmp/=2;
            
        }
    }
    cout<<endl<<"-----B[]-----"<<endl;
    for (int i=0; i<32; ++i) {
        cout<<B[i];
    }
}
void Des::GetNext()
{
    cout<<endl;
    for (int i=0; i<32; ++i) {
        PB[i]=B[P[i]-1]; //4*8
        nextR[i]=PB[i]^L[i];
        L[i]=R[i];
        R[i]=nextR[i];
    }
    cout<<endl<<"NEXT L[] IS:"<<endl;
    for (int i=0; i<32; ++i) {
        cout<<L[i];
    }
    cout<<endl<<"NEXT R[] IS:"<<endl;
    for (int i=0; i<32; ++i) {
        cout<<R[i];
    }
}

void Des::Encryption()
{
    cout<<"Input your key: (8 chars) "<<endl;
    cin>>key;
    while(key.length()!=8)
    {
        cout<<"Error,8 chars key needed: "<<endl;
        cin>>key;
    }
    cout<<"Input your message  (8 chars) "<<endl;
    cin>>message;
    while(message.length()!=8)
    {
    cout<<"Error,8 chars message needed: "<<endl;
    cin>>message;
    }
    KeyToBin();
    MsgToBin();
    FirstDo_En();
    GetFinKey();
    for (int i=0; i<16;++i)
    {
    GetFinMsg(i);
    FindFromS();
    GetNext();
    cout<<endl<<"-----ROUND "<<i+1<<" OVER-----"<<endl<<endl;
    }
    int FINTP[64];
    for (int i=0; i<32; ++i) {
        FINTP[i]=R[i];
        FINTP[i+32]=L[i];
    }
    
    for (int i=0; i<64; ++i) {
        FINAL[i]=FINTP[IP_1[i]-1];
    }
    
    cout<<"------FINAL BINARY-------"<<endl;
    for (int i=0; i<64; ++i) {
        cout<<FINAL[i];
    }
    
    cout<<endl;
    cout<<endl<<"-----FINAL CHAR------"<<endl;
    char FINCHAR[16];
    for (int i=0; i<16; ++i) {
        int tp=FINAL[i*4]*8+FINAL[i*4+1]*4+FINAL[i*4+2]*2+FINAL[i*4+3];
        if (tp<10) {
            FINCHAR[i]=tp+'0';
        }
        else
        {
        switch (tp) {
            case 10:
                FINCHAR[i]='A';
                break;
            case 11:
                FINCHAR[i]='B';
                break;
            case 12:
                FINCHAR[i]='C';
                break;
            case 13:
                FINCHAR[i]='D';
                break;
            case 14:
                FINCHAR[i]='E';
                break;
            case 15:
                FINCHAR[i]='F';
                break;
            default:
                break;
        }
        }
    }
    for (int i=0; i<16; ++i) {
        cout<<FINCHAR[i];
    }
    cout<<endl;
}

void Des::Decryption()
{
    cout<<endl<<"-----------Decryption HERE-----------"<<endl;
    cout<<"Input your key: (8 chars) "<<endl;
    cin>>key;
    while(key.length()!=8)
    {
        cout<<"Error,8 chars key needed: "<<endl;
        cin>>key;
    }
    cout<<"Input your ciphertext 16 chars(Hex like 96D0028878D58C89)"<<endl;
    cin>>ciphertext;
    while(ciphertext.length()!=16)
    {
        cout<<"Error,16 chars ciphertext needed: (Hex like 96D0028878D58C89)"<<endl;
        cin>>ciphertext;
    }
    CipToBin();
    KeyToBin();
    De_init();
    GetFinKey();
    for (int i = 15; i >= 0; --i)
    {
        GetFinMsg(i);
        FindFromS();
        GetNext();
    }
    cout<<endl<<endl<<"=-----GET FINAL BINARY MESSAGE---------"<<endl;
    int final_message[64];
    int final_message_dec[8];
    char final_message_char[8];
    int fin_tp[64];
    for (int i = 0; i < 32; ++i)
    {
        final_message[i]=R[i];
        final_message[i+32]=L[i];
    }
    for (int i = 0; i < 64; ++i)
    {
        fin_tp[i]=final_message[IP_1[i]-1];
    }
    for (int i = 0; i < 64; ++i)
    {
        final_message[i]=fin_tp[i];
        cout<<final_message[i];
    }
    cout<<endl<<"=-----FINAL DEC MESSAGE---------"<<endl;
    for (int i = 0; i < 8; ++i)
    {
        final_message_dec[i]=final_message[i*8]*128+final_message[i*8+1]*64+final_message[i*8+2]*32+final_message[i*8+3]*16+final_message[i*8+4]*8+final_message[i*8+5]*4+final_message[i*8+6]*2+final_message[i*8+7];
        final_message_char[i]=final_message_dec[i];
        cout<<final_message_dec[i]<<" ";
    }
    cout<<endl<<"=-----FINAL CHAR MESSAGE---------"<<endl;
    for (int i = 0; i < 8; ++i)
    {
        cout<<final_message_char[i];
    }
    cout<<endl;
}
void Des::CipToBin()
{
    int tp=0;
    for (int i = 0; i <16; ++i)
    {
        if (ciphertext[i]<'A')
        {
            tp=ciphertext[i]-'0';
        }
        else
            tp=ciphertext[i]-'A'+10;
        for (int j = 3; j >=0; --j)
        {
            cipherBin[i*4+j]=tp%2;
            tp/=2;
        }
    }
    cout<<endl<<"---ciphertext TO BIN ---"<<endl;
    for (int i = 0; i < 64; ++i)
    {
        cout<<cipherBin[i];
    }
    cout<<endl;

}
void Des::De_init()
{
    int i=0;
    
    for (int i=0; i<56;++i) {
        key_pc_1[i]=keybin[PC_1[i]-1];
    }
    //PC_1  __KEY

    for (i=0; i<28; ++i) {
        C[0][i]=key_pc_1[i];
        D[0][i]=key_pc_1[i+28];
    }
    //GET C & D __KEY

    int cipher_tp[64];
    for (i=0; i<64; ++i) {
        cipher_tp[i]=cipherBin[IP[i]-1];
    }
    //IP Transform
    cout<<endl<<"---LR----"<<endl;    
    for (i=0; i<32; ++i) {
        L[i]=cipher_tp[i];
        R[i]=cipher_tp[i+32];
        cout<<R[i];
    }
    //GET L R
    cout<<endl;
}
int main(int argc, char const *argv[])
{
	Des nedes;
    nedes.Encryption();
    nedes.Decryption();
	return 0;
}