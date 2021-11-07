module threefish512;

// memcpy
extern(C) nothrow @nogc void* memcpy(void* dst, const void* src, size_t n);

class Threefish512
{
	private {
		// Размер блока шифра
		enum blockSize = 64;
		// Количество 64-битных слов в ключе (и в блоке)
		enum Nw = 8;
		// Количество раундов
		enum Nr = 72;
		// Количество раундов (за вычетом последнего)
		enum Ns = Nr / 4;
		// Функция перестановки
		uint[8] p   = [2, 1, 4, 7, 6, 5, 0, 3];
		uint[8] p_1 = [6, 1, 0, 7, 2, 5, 4, 3];
		
		// Функция смешивания и перестановки
		uint[4][8] r = [ 
			[38, 30, 50, 53], 
			[48, 20, 43, 31], 
			[34, 14, 15, 27], 
			[26, 12, 58, 7 ],
			[33, 49, 8, 42 ], 
			[39, 27, 41, 14], 
			[29, 26, 11, 9 ], 
			[33, 51, 39, 35]
		];
		
		// Твик-значение (свободный параметр алгоритма)
		ulong[3] t;
		// Раундовые ключи
		ulong[8][Ns + 1] subKeys;
		
		auto _mix(ref ulong[2] x, ulong r, ref ulong[2] y)
		{
			y[0] = x[0] + x[1];
			y[1] = (x[1] << r) | (x[1] >> (64 - r));
			y[1] ^= y[0];
		}
		
		auto _demix(ref ulong[2] y, ulong r, ref ulong[2] x)
		{
			y[1] ^= y[0];
			x[1] = (y[1] << (64 - r)) | (y[1] >> r);
			x[0] = y[0] - x[1];
		}
		
		alias _mod8 = (ulong a) => a & 7UL;
	}
	
	/// Шифрование блока
	/// plain - указатель на блок для шифрования, c - массив-приемник результата
	void crypt(ulong* plainData, ulong* c) @system
	{
		ulong[8] f;
		ulong[8] e;
		ulong[2] y;
		ulong[2] x;
		ulong[8] v;
		uint i;
	
		memcpy (&v[0], plainData, 64);
	
		for (uint round = 0; round < Nr; round++)
		{
			if (round % 4 == 0)
			{
				uint s = round >> 2;
				
				for (i = 0; i < Nw; i++)
				{
					e[i] = v[i] + subKeys[s][i];
				}
			}
			else
			{
				for (i = 0; i < Nw; i++)
				{
					e[i] = v[i];
				}
			}
		
			for (i = 0; i < Nw / 2; i++)
			{
				x[0] = e[i * 2];
				x[1] = e[i * 2 + 1];
				
				_mix(x, r[_mod8(round)][i], y);
				
				f[i * 2] = y[0];
				f[i * 2 + 1] = y[1];
			}
		
			for (i = 0; i < Nw; i++)
			{
				v[i] = f[p[i]];
			}
		}
	
		for (i = 0; i < Nw; i++)
		{
			c[i] = v[i] + subKeys[Ns][i];
		}
	}
	
	/// Шифрование блока (безопасная версия)
	/// plain - массив с данными блока
	auto crypt(ulong[8] plainData)
	{
		ulong[8] c = 0;
		crypt(plainData.ptr, c.ptr);
		return c;
	}
	
	/// Дешифрование блока
	/// plain - указатель на блок для дешифрования, c - массив-приемник результата
	void decrypt(ulong* plainData, ulong* c) @system
	{
		ulong[8] f;
		ulong[8] e;
		ulong[2] y;
		ulong[2] x;
		ulong[8] v;
		uint i;
	
		memcpy(&v[0], plainData, 64);
	
		for (uint round = Nr; round > 0; round--)
		{
			if (round % 4 == 0)
			{
				uint s = round >> 2;
				for (i = 0; i < Nw; i++)
				{
					f[i] = v[i] - subKeys[s][i];
				}
			}
			else
			{
				for (i = 0; i < Nw; i++)
				{
					f[i] = v[i];
				}
			}
		
			for (i = 0; i < Nw; i++)
			{
				e[i] = f[p_1[i]];
			}
		
			for (i = 0; i < Nw / 2; i++)
			{
				y[0] = e[i * 2];
				y[1] = e[i * 2 + 1];
				
				_demix(y, r[_mod8(round - 1)][i], x);
				
				v[i * 2] = x[0];
				v[i * 2 + 1] = x[1];
			}
		}
	
		for (i = 0; i < Nw; i++)
		{
			c[i] = v[i] - subKeys[0][i];
		}
	}
	
	/// Дешифрование блока (безопасная версия)
	/// plain - массив с данными блока
	auto decrypt(ulong[8] plain)
	{
		ulong[8] c = 0;
		decrypt(plain.ptr, c.ptr);
		return c;
	}
	
	/// Подготовка раундовых ключей
	/// keyData - указатель на массив с ключом, tweakData - указатель на массив с твик-значением
	void setup(ulong* keyData, ulong* tweakData) @system
	{
		uint i;
		ulong[8] K;
		ulong[2] T;
		ulong[9] key;
	
		ulong kNw = 6148914691236517205L;
		
		memcpy(&K[0], &keyData[0], 64);
		memcpy(&T[0], &tweakData[0], 16);
			
		for (i = 0; i < Nw; i++)
		{
			kNw ^= K[i];
			key[i] = K[i];
		}
		
		key[8] = kNw;
		
		t[0] = T[0];
		t[1] = T[1];
		t[2] = T[0] ^ T[1];
	
		for (uint round = 0; round <= Ns; round++)
		{
			for (i = 0; i < Nw; i++)
			{
				subKeys[round][i] = key[(round + i) % (Nw + 1)];
				
				if (i == Nw - 3)
				{
					subKeys[round][i] += t[round % 3];
				}
				else if (i == Nw - 2)
				{
					subKeys[round][i] += t[(round + 1) % 3];
				}
				else if (i == Nw - 1)
				{
					subKeys[round][i] += round;
				}
			}
		}
	}
	
	/// Подготовка раундовых ключей (безопасная версия)
	/// keyData - указатель на массив с ключом, tweakData - указатель на массив с твик-значением
	void setup(ulong[8] keyData, ulong[2] tweakData)
	{
		setup(keyData.ptr, tweakData.ptr);
	}
}
