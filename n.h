typedef unsigned long long D;
using namespace std;

// -------------------------
namespace tpoollib
	{
	// Handles template

	// Destruction Policy	
	template<typename T>
	class destruction_policy
		{
		public:
			static void destruct(T h)
				{
				static_assert(false, "Must define destructor");
				}
		};

	// Policies Specialization
	template<>	class destruction_policy<PTP_POOL> { public: static void destruct(PTP_POOL h) { CloseThreadpool(h); } };
	template<>	class destruction_policy<PTP_WORK> { public: static void destruct(PTP_WORK h) { CloseThreadpoolWork(h); } };
	template<>	class destruction_policy<PTP_WAIT> { public: static void destruct(PTP_WAIT h) { CloseThreadpoolWait(h); } };
	template<>	class destruction_policy<PTP_TIMER> { public: static void destruct(PTP_TIMER h) { CloseThreadpoolTimer(h); } };
	template<>	class destruction_policy<PTP_IO> { public: static void destruct(PTP_IO h) { CloseThreadpoolIo(h); } };
	template<>	class destruction_policy<PTP_CLEANUP_GROUP> { public: static void destruct(PTP_CLEANUP_GROUP h) { CloseThreadpoolCleanupGroup(h); } };


	// Template for Handles
	template <typename T, typename Destruction = destruction_policy<T>>
	class xhandle
		{
		private:
			T hX = 0;
			bool NoDestruct = true;
			shared_ptr<size_t> ptr = make_shared<size_t>();

		public:

			bool Valid()
				{
				if (hX)
					return true;
				return false;
				}

			// Closing items
			void Close()
				{
				if (!ptr || !ptr.unique())
					{
					ptr.reset();
					return;
					}
				ptr.reset();
				if (hX != 0 && !NoDestruct)
					Destruction::destruct(hX);
				hX = 0;
				}

			xhandle()
				{
				hX = 0;
				}
			~xhandle()
				{
				Close();
				}
			xhandle(const xhandle& h)
				{
				Dup(h);
				}
			xhandle(xhandle&& h)
				{
				Move(std::forward<xhandle>(h));
				}
			xhandle(T hY, bool NoDestructOnClose)
				{
				hX = hY;
				NoDestruct = NoDestructOnClose;
				}

			xhandle& operator =(const xhandle& h)
				{
				Dup(h);
				return *this;
				}
			xhandle& operator =(xhandle&& h)
				{
				Move(std::forward<xhandle>(h));
				return *this;
				}

			void Dup(const xhandle& h)
				{
				Close();
				NoDestruct = h.NoDestruct;
				hX = h.hX;
				ptr = h.ptr;
				}
			void Move(xhandle&& h)
				{
				Close();
				hX = h.hX;
				ptr = h.ptr;
				NoDestruct = h.NoDestruct;
				h.ptr.reset();
				h.hX = 0;
				h.NoDestruct = false;
				}
			operator T() const
				{
				return hX;
				}

		};


	template <bool AutoDestruct = true>
	class tpool
		{
		private:
			xhandle<PTP_POOL> p;
			xhandle<PTP_CLEANUP_GROUP> pcg;
			TP_CALLBACK_ENVIRON env;

			tpool(const tpool&) = delete;
			tpool(tpool&&) = delete;
			void operator=(const tpool&) = delete;
			void operator=(tpool&&) = delete;

		public:

			tpool()
				{
				}

			~tpool()
				{
				End();
				}

			void End()
				{
				Join();
				DestroyThreadpoolEnvironment(&env);
				p.Close();
				}

			unsigned long nThreads = 0;

			// Creates the interfaces
			bool Create(unsigned long nmin = 1, unsigned long nmax = 1)
				{
				bool jauto = AutoDestruct;

				// Env
				InitializeThreadpoolEnvironment(&env);

				// Pool and Min/Max
				xhandle<PTP_POOL> cx(CreateThreadpool(0), false);
				p = cx;
				if (!p)
					{
					End();
					return false;
					}
				if (!SetThreadpoolThreadMinimum(p, nmin))
					{
					End();
					return false;
					}
				nThreads = nmax;
				SetThreadpoolThreadMaximum(p, nmax);

				// Cleanup Group
				if (jauto)
					{
					xhandle<PTP_CLEANUP_GROUP> cx2(CreateThreadpoolCleanupGroup(), false);
					pcg = cx2;
					if (!pcg)
						{
						End();
						return false;
						}
					}

				// Sets
				SetThreadpoolCallbackPool(&env, p);
				SetThreadpoolCallbackCleanupGroup(&env, pcg, 0);

				return true;
				}


			// Templates for each of the items, to be specialized later
			template <typename J>
			void Wait(xhandle<J> h, bool Cancel = false)
				{
				static_assert(false, "No Wait function is defined");
				}
			template <typename J, typename CB_J>
			xhandle<J> CreateItem(CB_J cb, PVOID opt = 0, HANDLE hX = 0)
				{
				static_assert(false, "No Create function is defined");
				}
			template <typename J, typename ...A>
			void RunItem(xhandle<J> h, std::tuple<A...> = std::make_tuple<>())
				{
				static_assert(false, "No Run function is defined");
				}


			// Work Stuff
			template <> xhandle<PTP_WORK> CreateItem<PTP_WORK, PTP_WORK_CALLBACK>(PTP_WORK_CALLBACK cb, PVOID opt, HANDLE)
				{
				xhandle<PTP_WORK> a(CreateThreadpoolWork(cb, opt, &env), AutoDestruct);
				return a;
				}
			template <> void RunItem<PTP_WORK>(xhandle<PTP_WORK> h, std::tuple<>)
				{
				SubmitThreadpoolWork(h);
				}
			template <> void Wait<PTP_WORK>(xhandle<PTP_WORK> h, bool Cancel)
				{
				WaitForThreadpoolWorkCallbacks(h, Cancel);
				}


			// Wait  stuff
			template <> xhandle<PTP_WAIT> CreateItem<PTP_WAIT, PTP_WAIT_CALLBACK>(PTP_WAIT_CALLBACK cb, PVOID opt, HANDLE)
				{
				xhandle<PTP_WAIT> a(CreateThreadpoolWait(cb, opt, &env), AutoDestruct);
				return a;
				}
			template <> void Wait<PTP_WAIT>(xhandle<PTP_WAIT> h, bool Cancel)
				{
				WaitForThreadpoolWaitCallbacks(h, Cancel);
				}

			// Timer stuff
			template <> xhandle<PTP_TIMER> CreateItem<PTP_TIMER, PTP_TIMER_CALLBACK>(PTP_TIMER_CALLBACK cb, PVOID opt, HANDLE)
				{
				xhandle<PTP_TIMER> a(CreateThreadpoolTimer(cb, opt, &env), AutoDestruct);
				return a;
				}
			template <> void RunItem<PTP_TIMER>(xhandle<PTP_TIMER> h, std::tuple<FILETIME*, DWORD, DWORD>t)
				{
				SetThreadpoolTimer(h, std::get<0>(t), std::get<1>(t), std::get<2>(t));
				}
			template <> void Wait<PTP_TIMER>(xhandle<PTP_TIMER> h, bool Cancel)
				{
				WaitForThreadpoolTimerCallbacks(h, Cancel);
				}

			// IO Stuff
			template <> xhandle<PTP_IO> CreateItem<PTP_IO, PTP_WIN32_IO_CALLBACK>(PTP_WIN32_IO_CALLBACK cb, PVOID opt, HANDLE hY)
				{
				xhandle<PTP_IO> a(CreateThreadpoolIo(hY, cb, opt, &env), AutoDestruct);
				return a;
				}
			template <> void RunItem<PTP_IO>(xhandle<PTP_IO> h, std::tuple<bool> t)
				{
				bool Cancel = std::get<0>(t);
				if (Cancel)
					CancelThreadpoolIo(h);
				else
					StartThreadpoolIo(h);
				}
			template <> void Wait<PTP_IO>(xhandle<PTP_IO> h, bool Cancel)
				{
				WaitForThreadpoolIoCallbacks(h, Cancel);
				}

			// Join functions, one for each option (AutoDestruct or not)
			template <bool Q = AutoDestruct>
			typename std::enable_if<Q, void>::type
				Join(bool Cancel = false)
				{
				if (pcg)
					{
					CloseThreadpoolCleanupGroupMembers(pcg, Cancel, 0);
					//					pcg.Close();
					}
				}

			template <bool Q = AutoDestruct>
			typename std::enable_if<!Q, void>::type
				Join(bool Cancel = false,
					std::initializer_list<xhandle<PTP_WORK>> h1 = std::initializer_list<xhandle<PTP_WORK>>({}),
					std::initializer_list<xhandle<PTP_TIMER>> h2 = std::initializer_list<xhandle<PTP_TIMER>>({}),
					std::initializer_list<xhandle<PTP_WAIT>> h3 = std::initializer_list<xhandle<PTP_WAIT>>({}),
					std::initializer_list<xhandle<PTP_IO>> h4 = std::initializer_list<xhandle<PTP_IO>>({})
					)
				{
				for (auto a : h1)
					Wait<PTP_WORK>(a, Cancel);
				for (auto a : h2)
					Wait<PTP_TIMER>(a, Cancel);
				for (auto a : h3)
					Wait<PTP_WAIT>(a, Cancel);
				for (auto a : h4)
					Wait<PTP_IO>(a, Cancel);
				}

		};

	}

class N;

N operator + (const N& lhs, const N& rhs);
N operator - (const N& lhs, const N& rhs);
N operator / (const N& lhs, const N& rhs);
N operator % (const N& lhs, const N& rhs);
N operator | (const N& lhs, const N& rhs);
N operator & (const N& lhs, const N& rhs);
N operator ^ (const N& lhs, const N& rhs);

class N
	{
	private:

#ifdef _DEBUG
		string sr;
		void srx()
			{
			sr = s(b,true);
			}
#endif

		unsigned long long b = 10;
		vector<D> n;
		bool m = false;
#ifdef _WIN64
		typedef signed long long ssize_t;
#else
		typedef signed long ssize_t;
#endif

	public:

		void clear()
			{
			n.clear();
			m = false;
			}

		void RemoveZeroes()
			{
			while (n.size() > 0)
				{
				if (n[n.size() - 1] != 0)
					break;
				n.erase(n.end() - 1);
				}
#ifdef _DEBUG
			srx();
#endif
			}

		static N rand(N to = 100000000LL)
			{
			HCRYPTPROV hProvider = 0;
			if (!::CryptAcquireContextW(&hProvider, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
				return (unsigned long long)::rand();
			to = to.tobase(16);
			auto digsfar = to.NumDigits();

			vector<BYTE> pbBuffer(digsfar/2);

			if (!::CryptGenRandom(hProvider, (DWORD)pbBuffer.size(), pbBuffer.data()))
				{
				::CryptReleaseContext(hProvider, 0);
				return (unsigned long long)::rand();
				}


			string rx;
			for (size_t i = 0; i < pbBuffer.size(); ++i)
				{
				auto j = pbBuffer[i];
				char x[10];
				sprintf_s(x, 10, "%02X", j);
				rx += x;
				}
			N res(rx.c_str(), 16);
			if (res <= to)
				return res;
			return get<1>(w_div(res, to));
			}

		bool IsEven()
			{
			if (NumDigits() == 0)
				return true;
			if ((n[0] % 2) == 0)
				return true;
			return false;
			}



		bool IsZero() const
			{
			return NumDigits() == 0;
			}

		size_t NumDigits() const
			{
			return n.size();
			}

		D operator[](size_t idx) const
			{
			if (n.size() <= idx)
				return 0;
			return n[idx];
			}

		void shl2(size_t t2)
			{
			while (t2 > 0)
				{
				*this *= 2LL;
				t2--;
				}
			}

		void shr2(size_t t2)
			{
			while (t2 > 0)
				{
				*this /= 2LL;
				t2--;
				}
			}


		N& operator <<=(size_t t2)
			{
			shl2(t2);
			return *this;
			}

		N& operator >>=(size_t t2)
			{
			shr2(t2);
			return *this;
			}

		N& operator &=(const N& t2)
			{
			*this = w_logical(*this,t2, 0);
			return *this;
			}

		N& operator |=(const N& t2)
			{
			*this = w_logical(*this, t2, 1);
			return *this;
			}
		N& operator ^=(const N& t2)
			{
			if (b == 2)
				*this = w_logical(*this, t2, 2);
			else
				*this = w_pow(*this, t2);
			return *this;
			}


		N cshl(int t) const
			{
			N a = *this;
			a.shl(t);
			return a;
			}

		N cshr(int t) const
			{
			N a = *this;
			a.shr(t);
			return a;
			}

		void shr(size_t t)
			{
			if (NumDigits() <= t)
				clear();
			else
				{
				for(size_t i = 0 ; i < t ; i++)
					n.erase(n.end() - 1);
				}
#ifdef _DEBUG
			srx();
#endif
			}
		void shl(size_t t)
			{
			D d = 0;
			for (size_t  i = 0; i < t; i++)
				n.insert(n.begin(),d);
#ifdef _DEBUG
			srx();
#endif
			}



		static bool Less(const N& n1, const N& n2)
			{
			if (n1.m != n2.m)
				{
				if (n1.m == true)
					return true;
				return false;
				}
			if (n1.n.size() < n2.n.size())
				return true;
			if (n1.n.size() > n2.n.size())
				return false;

			for (ssize_t j = n1.n.size() - 1; j >= 0; j--)
				{
				D d1 = n1.n[j];
				D d2 = n2.n[j];
				if (d1 < d2)
					return true;
				if (d1 > d2)
					return false;
				}
			return false;
			}

		static bool Equal(const N& n1, const N& n2)
			{
			if (n1.m == n2.m && n1.n == n2.n)
				return true;
			return false;
			}


		bool operator <(const N& n2) const
			{
			return Less(*this, n2);
			}
		bool operator >(const N& n2) const
			{
			return Less(n2,*this);
			}
		bool operator <=(const N& n2) const
			{
			return !Less(n2, *this);
			}
		bool operator >=(const N& n2) const
			{
			return !Less(*this, n2);
			}
		bool operator !=(const N& n2) const
			{
			return !Equal(*this, n2);
			}
		bool operator ==(const N& n2) const
			{
			return Equal(*this, n2);
			}
		N& operator ++()
			{
			N nx((signed long long)1);
			return operator +=(nx);
			}
		N& operator --()
			{
			N nx((signed long long)1);
			return operator -=(nx);
			}

		static N w_subx(const N& n1, const N& n2)
			{
			if (n1.m != n2.m)
				return w_add(n1, n2.negative());
				
			if (n1.absolute() < n2.absolute())
				return w_subx(n2, n1).negative();

			if (n2.IsZero())
				return n1;
			if (n1.IsZero())
				return n2.negative();

			N n;
			n.ChangeInternalBase(n1.b);
			n.m = n1.m;
			int carry = 0;

			for (size_t i = 0; i < n1.NumDigits() || i < n2.NumDigits(); i++)
				{
				signed long long sum = n1[i] - n2[i] + carry;
				carry = 0;
				if (sum < 0)
					{
					sum = n1.b + sum;
					carry = -1;
					}
				n.n.push_back(sum);
#ifdef _DEBUG
				n.srx();
#endif
				}
			n.n.push_back(carry);
			n.RemoveZeroes();
			return n;
			}


		static N w_pow(const N& n1, const N& n2)
			{
			N z = n1;
			if (n2 == 0ll)
				return 1ll;
			if (n2 == 1ll)
				return n1;
			if (n1 == 1ll)
				return 1ll;

			for (N j = 1ll; j < n2; ++j)
				z *= n1;

#ifdef _DEBUG
			z.srx();
#endif
			return z;
			}

		static N w_add2(vector<N>& n, tpoollib::tpool<>& pool)
			{
			if (n.size() == 0)
				return 0LL;
			if (n.size() == 1)
				return n[0];
			if (n.size() == 2)
				{
				N res = n[0];
				res += n[1];
				return res;
				}
			struct Z
				{
				N* n1;
				N* n2;
				N* res;
				};
			vector<Z> z(n.size());
			vector<N> res(n.size() / 2);

			for (size_t i = 0; i < n.size(); i += 2)
				{
				if (i == (n.size() - 1))
					break; // odd number of additions

				auto a = [](PTP_CALLBACK_INSTANCE, PVOID j, PTP_WORK)
					{
					Z* z = (Z*)j;
					*z->res = w_add(*z->n1,*z->n2);
					};
				Z& zz = z[i];
				zz.n1 = &n[i];
				zz.n2 = &n[i + 1];
				zz.res = &res[i / 2];

				auto wo = pool.CreateItem<PTP_WORK, PTP_WORK_CALLBACK>(a, (PVOID)&zz);
				pool.RunItem(wo);
				}
			pool.Join();
			if (n.size() % 2)
				res.push_back(n[n.size() - 1]);
			return w_add2(res,pool);
			}


		static N w_pow2(const N& n1, const N& n2,tpoollib::tpool<>& pool)
			{
			N z = n1;
			if (n2 == 0ll)
				return 1ll;
			if (n2 == 1ll)
				return n1;
			if (n1 == 1ll)
				return 1ll;

			for (N j = 1ll; j < n2; ++j)
				z = w_mul2(z, n1,pool);
			return z;
			}

		static N w_mul2(const N& n1, const N& n2, tpoollib::tpool<>& pool)
			{
			size_t muls = n1.NumDigits() * n2.NumDigits();
			vector<N> a;
			a.reserve(muls);
			for (size_t i = 0; i < n1.NumDigits(); i++)
				{
				for (size_t ii = 0; ii < n2.NumDigits(); ii++)
					{
					N rr;
					D d1 = n1[i];
					D d2 = n2[ii];
					unsigned long long r = d1 * d2;
					rr = r;
					rr.shl(ii + i);
					a.push_back(rr);
					}
				}
			return w_add2(a,pool);
			}

		static tuple<N, N> w_div(const N& n1, const N& n2,bool NoChangeBase = false)
			{
			if (n1.b != n2.b && NoChangeBase == false)
				return w_div(n1.b, n2.tobase(n1.b));
			if (n2 > n1)
				{
				N res = n1;
				return std::make_tuple<N, N>(0LL, std::forward<N>(res));
				}
			if (n2 == n1)
				return std::make_tuple<N, N>(1LL, 0LL);

			N rem = n1;
			N res;
			res.ChangeInternalBase(n1.b);

			for (;;)
				{
				auto nd2 = n2.NumDigits();
				auto upper = rem.upperpart(nd2);
				if (upper < n2)
					{
					nd2++;
					upper = rem.upperpart(nd2);
					if (upper < n2)
						{
						// End...
						return std::make_tuple<N, N>(forward<N>(res), forward<N>(rem));
						}
					}

				unsigned long long js = 9;
				N m1;
				for (; js >= 1; js--)
					{
					m1 = w_mul(n2, js);
					if (m1 < upper)
						break;
					}

				res.n.insert(res.n.begin(),js);
#ifdef _DEBUG
				res.srx();
#endif
				upper -= m1;
				upper.shl(rem.NumDigits() - nd2);
				upper += rem.lowerpart(rem.NumDigits() - nd2);
				rem = upper;
				}
			}

		static N w_mul(const N& n1, const N& n2)
			{
			if (n1.b != n2.b)
				return w_mul(n1, n2.tobase(n1.b));
			N n;
			n.ChangeInternalBase(n1.b);
			vector<N> addiz;
			for (size_t i = 0; i < n1.n.size(); i++)
				{
				D d1 = n1.n[i];
				N addi;
				addi.n.reserve(i + n2.n.size());
				for (size_t j = 0; j < i; j++)
					addi.n.push_back(0);
				D carry = 0;
				for (size_t y = 0; y < n2.n.size(); y++)
					{
					D d2 = n2.n[y];
					D dm = (d1*d2) + carry;
					carry = 0;
					carry = dm / n1.b;
					dm %= n1.b;
					addi.n.push_back(dm);
#ifdef _DEBUG
					addi.srx();
#endif
					}
				addi.n.push_back(carry);
				addi.RemoveZeroes();
				addiz.push_back(addi);
				}
			for (auto& a : addiz)
				n += a;
			if (n1.m != n2.m)
				n.m = true;
			return n;
			}

		static N w_logical(const N& n1, const N& n2,int x)
			{
			if (n1.b != 2)
				return w_logical(n1.tobase(2),n2,x);
			if (n2.b != 2)
				return w_logical(n1, n2.tobase(2),x);

			N n;
			n.ChangeInternalBase(2);
			n.n.reserve(max(n1.NumDigits(), n2.NumDigits()));

			for (size_t i = 0; i < n1.NumDigits() || i < n2.NumDigits(); i++)
				{
				D sum = 0;
				if (x == 0) sum = n1[i] & n2[i];
				if (x == 1) sum = n1[i] | n2[i];
				if (x == 2) sum = n1[i] ^ n2[i];
				n.n.push_back(sum);
#ifdef _DEBUG
				n.srx();
#endif
				}
			n.RemoveZeroes();
			return n;
			}


		static N w_add(const N& n1, const N& n2)
			{
			if (n1.b != n2.b)
				return w_add(n1, n2.tobase(n1.b));
			if (n1.m != n2.m)
				{
				if (n1.m)
					return w_subx(n2, n1.negative());
				return w_subx(n1, n2.negative());
				}
			if (n1.n.empty()) return n2;
			if (n2.n.empty()) return n1;

			N n;
			n.ChangeInternalBase(n1.b);
			n.n.reserve(max(n1.NumDigits(), n2.NumDigits()));
			D carry = 0;

			if (n1.m && n2.m)
				n.m = true;

			size_t j = 0;
			for (size_t i = 0; i < n1.NumDigits() || i < n2.NumDigits() ; i++)
				{
				j = i;
				D sum = n1[i] + n2[i] + carry;
				carry = 0;
				if (sum >= n1.b)
					{
					carry = 1;
					sum -= n1.b;
					}
				n.n.push_back(sum);
#ifdef _DEBUG
				n.srx();
#endif
				}
			n.n.push_back(carry);
			n.RemoveZeroes();
			return n;
			}


		N& operator += (const N& nn)
			{
			*this = w_add(*this, nn);
			return *this;
			}
		N& operator -= (const N& nn)
			{
			*this = w_add(*this, nn.negative());
			return *this;
			}
		N& operator *= (const N& nn)
			{
			*this = w_mul(*this, nn);
			return *this;
			}
		N& operator /= (const N& nn)
			{
			*this = std::get<0>(w_div(*this, nn));
			return *this;
			}
		N& operator %= (const N& nn)
			{
			*this = std::get<1>(w_div(*this, nn));
			return *this;
			}
		
		void ChangeInternalBase(unsigned long long nb = 10)
			{
			b = nb;
			}

		N tobase(unsigned long long nb) const
			{
			N n2(s(nb).c_str(), nb);
			return n2;
			}

		N& ParseBase(const char* a1,unsigned long long B = 16)
			{
			N res;
			res.b = b;
			unsigned long long  k = 0;
			for (ssize_t i = strlen(a1) - 1; i >= 0; i--)
				{
				unsigned long long j = a1[i];
				if (j >= 'a')
					j -= ('a' - 10);
				else
				if (j >= 'A')
					j -= ('A' - 10);
				else
				if (j >= '0')
					j -= '0';

				if (j >= B)
					break; // duh
				auto p = w_pow(B, k);
				p *= j;
				res += p;
				k++;
				}
			operator =(res);
			return *this;
			}


		N lowerpart(size_t digs)
			{
			if (digs > NumDigits())
				digs = NumDigits();
			N n2 = *this;
			auto b1 = n.begin();
			auto e1 = n.begin() + digs;
			vector<D> nv(b1, e1);
			n2.n = nv;
#ifdef _DEBUG
			n2.srx();
#endif
			return n2;
			}

		D upperdigit() const
			{
			return n[n.size() - 1];
			}

		N upperpart(size_t digs)
			{
			if (digs > NumDigits())
				digs = NumDigits();
			N n2 = *this;
			auto b1 = n.end();
			auto e1 = n.end() - digs;
			vector<D> nv(e1, b1);
			n2.n = nv;
#ifdef _DEBUG
			n2.srx();
#endif
			return n2;
			}

		N negative() const
			{
			N nx = *this;
			nx.m = !nx.m;
#ifdef _DEBUG
			nx.srx();
#endif
			return nx;
			}

		N absolute() const
			{
			N nn = *this;
			nn.m = false;
#ifdef _DEBUG
			nn.srx();
#endif
			return nn;
			}




		string s(unsigned long long base = -1,bool Debug = false) const
			{
			if (base == (unsigned long long)-1)
				base = b;
			if (base == 0)
				return "";
			string a;
			if (base == b)
				{
				if (n.empty())
					return "0";

				if (m)
					a += "-";
				for (ssize_t j = (n.size() - 1); j >= 0; j--)
					{
					auto d = n[j];
					if (d >= 10)
						a += (char)(d + 'A' - 10);
					else
						a += (char)(d + 0x30u);
					}
				return a;
				}
			if (Debug)
				return "";

			N e = *this;
			if (m)
				a += "-";
			for (;;)
				{
				auto rx = w_div(e, base,true);
				auto d = atoi(get<1>(rx).s().c_str());
				if (d >= 10)
					d = (d - 10) + 'A';
				else
					d += 0x30;
				a += (char)d;
				e = get<0>(rx);
				if (e.IsZero())
					break;
				}
			std::reverse(a.begin(), a.end());
			return a;
			}

		void Set(unsigned long long a = 0)
			{
			n.clear();
			m = false;
			for (;;)
				{
				D d = a % b;
				n.push_back(d);
				a /= b;
				if (!a)
					break;
				}
			RemoveZeroes();
#ifdef _DEBUG
			srx();
#endif
			}

		void Set(signed long long a = 0)
			{
			n.clear();
			m = false;
			if (a < 0)
				{
				Set((unsigned long long)-a);
				m = true;
				}
			else
				Set((unsigned long long)a);
#ifdef _DEBUG
			srx();
#endif
			}


		void Set(const char* a)
			{
			n.clear();
			m = false;
			if (!a)
				return;
			for (size_t i = 0; i < strlen(a); i++)
				{
				char a1 = a[i];
				if (i == 0 && a1 == '-')
					{
					m = true;
					continue;
					}
				if (i == 0 && a1 == '+')
					{
					m = false;
					continue;
					}

				int jn = 0;

				if (a1 < '0')
					break;
				if (a1 >= 'a')
					jn = a1 - ('a' - 10);
				else
					if (a1 >= 'A')
						jn = a1 - ('A' - 10);
					else
						if (a1 >= '0')
							jn = a1 - ('0');
				if (jn >= b)
					break;
		
				n.insert(n.begin(),jn);
				}
			RemoveZeroes();
#ifdef _DEBUG
			srx();
#endif
			}


		N(const char* a,unsigned long long ba = 10)
			{
			b = ba;
			Set(a);
			}
		N(unsigned long long a)
			{
			Set(a);
			}
		N(signed long long a = 0)
			{
			Set(a);
			}
		N& operator=(unsigned long long a)
			{
			Set(a);
			return *this;
			}
		N& operator=(signed long long a)
			{
			Set(a);
			return *this;
			}
		N& operator=(const char* a)
			{
			Set(a);
			return *this;
			}


	};

#if 0
	// The following section was moved to mathutils.cpp to allow more than one module to link to it
N operator + (const N& lhs, const N& rhs)
	{
	N n = lhs;
	n += rhs;
	return n;
	}

N operator - (const N& lhs, const N& rhs)
	{
	N n = lhs;
	n -= rhs;
	return n;
	}

N operator / (const N& lhs, const N& rhs)
	{
	N n = lhs;
	n /= rhs;
	return n;
	}

N operator % (const N& lhs, const N& rhs)
	{
	N n = lhs;
	n %= rhs;
	return n;
	}

N operator | (const N& lhs, const N& rhs)
	{
	N n = lhs;
	n |= rhs;
	return n;
	}

N operator & (const N& lhs, const N& rhs)
	{
	N n = lhs;
	n &= rhs;
	return n;
	}

N operator ^ (const N& lhs, const N& rhs)
	{
	N n = lhs;
	n ^= rhs;
	return n;
	}
#endif