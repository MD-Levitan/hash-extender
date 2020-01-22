package hasher

import (
	"bytes"
	"fmt"
)

var t1 = [...]uint64{
	0x02aab17cf7e90c5e, 0xac424b03e243a8ec, 0x72cd5be30dd5fcd3, 0x6d019b93f6f97f3a,
	0xcd9978ffd21f9193, 0x7573a1c9708029e2, 0xb164326b922a83c3, 0x46883eee04915870,
	0xeaace3057103ece6, 0xc54169b808a3535c, 0x4ce754918ddec47c, 0x0aa2f4dfdc0df40c,
	0x10b76f18a74dbefa, 0xc6ccb6235ad1ab6a, 0x13726121572fe2ff, 0x1a488c6f199d921e,
	0x4bc9f9f4da0007ca, 0x26f5e6f6e85241c7, 0x859079dbea5947b6, 0x4f1885c5c99e8c92,
	0xd78e761ea96f864b, 0x8e36428c52b5c17d, 0x69cf6827373063c1, 0xb607c93d9bb4c56e,
	0x7d820e760e76b5ea, 0x645c9cc6f07fdc42, 0xbf38a078243342e0, 0x5f6b343c9d2e7d04,
	0xf2c28aeb600b0ec6, 0x6c0ed85f7254bcac, 0x71592281a4db4fe5, 0x1967fa69ce0fed9f,
	0xfd5293f8b96545db, 0xc879e9d7f2a7600b, 0x860248920193194e, 0xa4f9533b2d9cc0b3,
	0x9053836c15957613, 0xdb6dcf8afc357bf1, 0x18beea7a7a370f57, 0x037117ca50b99066,
	0x6ab30a9774424a35, 0xf4e92f02e325249b, 0x7739db07061ccae1, 0xd8f3b49ceca42a05,
	0xbd56be3f51382f73, 0x45faed5843b0bb28, 0x1c813d5c11bf1f83, 0x8af0e4b6d75fa169,
	0x33ee18a487ad9999, 0x3c26e8eab1c94410, 0xb510102bc0a822f9, 0x141eef310ce6123b,
	0xfc65b90059ddb154, 0xe0158640c5e0e607, 0x884e079826c3a3cf, 0x930d0d9523c535fd,
	0x35638d754e9a2b00, 0x4085fccf40469dd5, 0xc4b17ad28be23a4c, 0xcab2f0fc6a3e6a2e,
	0x2860971a6b943fcd, 0x3dde6ee212e30446, 0x6222f32ae01765ae, 0x5d550bb5478308fe,
	0xa9efa98da0eda22a, 0xc351a71686c40da7, 0x1105586d9c867c84, 0xdcffee85fda22853,
	0xccfbd0262c5eef76, 0xbaf294cb8990d201, 0xe69464f52afad975, 0x94b013afdf133e14,
	0x06a7d1a32823c958, 0x6f95fe5130f61119, 0xd92ab34e462c06c0, 0xed7bde33887c71d2,
	0x79746d6e6518393e, 0x5ba419385d713329, 0x7c1ba6b948a97564, 0x31987c197bfdac67,
	0xde6c23c44b053d02, 0x581c49fed002d64d, 0xdd474d6338261571, 0xaa4546c3e473d062,
	0x928fce349455f860, 0x48161bbacaab94d9, 0x63912430770e6f68, 0x6ec8a5e602c6641c,
	0x87282515337ddd2b, 0x2cda6b42034b701b, 0xb03d37c181cb096d, 0xe108438266c71c6f,
	0x2b3180c7eb51b255, 0xdf92b82f96c08bbc, 0x5c68c8c0a632f3ba, 0x5504cc861c3d0556,
	0xabbfa4e55fb26b8f, 0x41848b0ab3baceb4, 0xb334a273aa445d32, 0xbca696f0a85ad881,
	0x24f6ec65b528d56c, 0x0ce1512e90f4524a, 0x4e9dd79d5506d35a, 0x258905fac6ce9779,
	0x2019295b3e109b33, 0xf8a9478b73a054cc, 0x2924f2f934417eb0, 0x3993357d536d1bc4,
	0x38a81ac21db6ff8b, 0x47c4fbf17d6016bf, 0x1e0faadd7667e3f5, 0x7abcff62938beb96,
	0xa78dad948fc179c9, 0x8f1f98b72911e50d, 0x61e48eae27121a91, 0x4d62f7ad31859808,
	0xeceba345ef5ceaeb, 0xf5ceb25ebc9684ce, 0xf633e20cb7f76221, 0xa32cdf06ab8293e4,
	0x985a202ca5ee2ca4, 0xcf0b8447cc8a8fb1, 0x9f765244979859a3, 0xa8d516b1a1240017,
	0x0bd7ba3ebb5dc726, 0xe54bca55b86adb39, 0x1d7a3afd6c478063, 0x519ec608e7669edd,
	0x0e5715a2d149aa23, 0x177d4571848ff194, 0xeeb55f3241014c22, 0x0f5e5ca13a6e2ec2,
	0x8029927b75f5c361, 0xad139fabc3d6e436, 0x0d5df1a94ccf402f, 0x3e8bd948bea5dfc8,
	0xa5a0d357bd3ff77e, 0xa2d12e251f74f645, 0x66fd9e525e81a082, 0x2e0c90ce7f687a49,
	0xc2e8bcbeba973bc5, 0x000001bce509745f, 0x423777bbe6dab3d6, 0xd1661c7eaef06eb5,
	0xa1781f354daacfd8, 0x2d11284a2b16affc, 0xf1fc4f67fa891d1f, 0x73ecc25dcb920ada,
	0xae610c22c2a12651, 0x96e0a810d356b78a, 0x5a9a381f2fe7870f, 0xd5ad62ede94e5530,
	0xd225e5e8368d1427, 0x65977b70c7af4631, 0x99f889b2de39d74f, 0x233f30bf54e1d143,
	0x9a9675d3d9a63c97, 0x5470554ff334f9a8, 0x166acb744a4f5688, 0x70c74caab2e4aead,
	0xf0d091646f294d12, 0x57b82a89684031d1, 0xefd95a5a61be0b6b, 0x2fbd12e969f2f29a,
	0x9bd37013feff9fe8, 0x3f9b0404d6085a06, 0x4940c1f3166cfe15, 0x09542c4dcdf3defb,
	0xb4c5218385cd5ce3, 0xc935b7dc4462a641, 0x3417f8a68ed3b63f, 0xb80959295b215b40,
	0xf99cdaef3b8c8572, 0x018c0614f8fcb95d, 0x1b14accd1a3acdf3, 0x84d471f200bb732d,
	0xc1a3110e95e8da16, 0x430a7220bf1a82b8, 0xb77e090d39df210e, 0x5ef4bd9f3cd05e9d,
	0x9d4ff6da7e57a444, 0xda1d60e183d4a5f8, 0xb287c38417998e47, 0xfe3edc121bb31886,
	0xc7fe3ccc980ccbef, 0xe46fb590189bfd03, 0x3732fd469a4c57dc, 0x7ef700a07cf1ad65,
	0x59c64468a31d8859, 0x762fb0b4d45b61f6, 0x155baed099047718, 0x68755e4c3d50baa6,
	0xe9214e7f22d8b4df, 0x2addbf532eac95f4, 0x32ae3909b4bd0109, 0x834df537b08e3450,
	0xfa209da84220728d, 0x9e691d9b9efe23f7, 0x0446d288c4ae8d7f, 0x7b4cc524e169785b,
	0x21d87f0135ca1385, 0xcebb400f137b8aa5, 0x272e2b66580796be, 0x3612264125c2b0de,
	0x057702bdad1efbb2, 0xd4babb8eacf84be9, 0x91583139641bc67b, 0x8bdc2de08036e024,
	0x603c8156f49f68ed, 0xf7d236f7dbef5111, 0x9727c4598ad21e80, 0xa08a0896670a5fd7,
	0xcb4a8f4309eba9cb, 0x81af564b0f7036a1, 0xc0b99aa778199abd, 0x959f1ec83fc8e952,
	0x8c505077794a81b9, 0x3acaaf8f056338f0, 0x07b43f50627a6778, 0x4a44ab49f5eccc77,
	0x3bc3d6e4b679ee98, 0x9cc0d4d1cf14108c, 0x4406c00b206bc8a0, 0x82a18854c8d72d89,
	0x67e366b35c3c432c, 0xb923dd61102b37f2, 0x56ab2779d884271d, 0xbe83e1b0ff1525af,
	0xfb7c65d4217e49a9, 0x6bdbe0e76d48e7d4, 0x08df828745d9179e, 0x22ea6a9add53bd34,
	0xe36e141c5622200a, 0x7f805d1b8cb750ee, 0xafe5c7a59f58e837, 0xe27f996a4fb1c23c,
	0xd3867dfb0775f0d0, 0xd0e673de6e88891a, 0x123aeb9eafb86c25, 0x30f1d5d5c145b895,
	0xbb434a2dee7269e7, 0x78cb67ecf931fa38, 0xf33b0372323bbf9c, 0x52d66336fb279c74,
	0x505f33ac0afb4eaa, 0xe8a5cd99a2cce187, 0x534974801e2d30bb, 0x8d2d5711d5876d90,
	0x1f1a412891bc038e, 0xd6e2e71d82e56648, 0x74036c3a497732b7, 0x89b67ed96361f5ab,
	0xffed95d8f1ea02a2, 0xe72b3bd61464d43d, 0xa6300f170bdc4820, 0xebc18760ed78a77a,
}

var t2 = [...]uint64{
	0xe6a6be5a05a12138, 0xb5a122a5b4f87c98, 0x563c6089140b6990, 0x4c46cb2e391f5dd5,
	0xd932addbc9b79434, 0x08ea70e42015aff5, 0xd765a6673e478cf1, 0xc4fb757eab278d99,
	0xdf11c6862d6e0692, 0xddeb84f10d7f3b16, 0x6f2ef604a665ea04, 0x4a8e0f0ff0e0dfb3,
	0xa5edeef83dbcba51, 0xfc4f0a2a0ea4371e, 0xe83e1da85cb38429, 0xdc8ff882ba1b1ce2,
	0xcd45505e8353e80d, 0x18d19a00d4db0717, 0x34a0cfeda5f38101, 0x0be77e518887caf2,
	0x1e341438b3c45136, 0xe05797f49089ccf9, 0xffd23f9df2591d14, 0x543dda228595c5cd,
	0x661f81fd99052a33, 0x8736e641db0f7b76, 0x15227725418e5307, 0xe25f7f46162eb2fa,
	0x48a8b2126c13d9fe, 0xafdc541792e76eea, 0x03d912bfc6d1898f, 0x31b1aafa1b83f51b,
	0xf1ac2796e42ab7d9, 0x40a3a7d7fcd2ebac, 0x1056136d0afbbcc5, 0x7889e1dd9a6d0c85,
	0xd33525782a7974aa, 0xa7e25d09078ac09b, 0xbd4138b3eac6edd0, 0x920abfbe71eb9e70,
	0xa2a5d0f54fc2625c, 0xc054e36b0b1290a3, 0xf6dd59ff62fe932b, 0x3537354511a8ac7d,
	0xca845e9172fadcd4, 0x84f82b60329d20dc, 0x79c62ce1cd672f18, 0x8b09a2add124642c,
	0xd0c1e96a19d9e726, 0x5a786a9b4ba9500c, 0x0e020336634c43f3, 0xc17b474aeb66d822,
	0x6a731ae3ec9baac2, 0x8226667ae0840258, 0x67d4567691caeca5, 0x1d94155c4875adb5,
	0x6d00fd985b813fdf, 0x51286efcb774cd06, 0x5e8834471fa744af, 0xf72ca0aee761ae2e,
	0xbe40e4cdaee8e09a, 0xe9970bbb5118f665, 0x726e4beb33df1964, 0x703b000729199762,
	0x4631d816f5ef30a7, 0xb880b5b51504a6be, 0x641793c37ed84b6c, 0x7b21ed77f6e97d96,
	0x776306312ef96b73, 0xae528948e86ff3f4, 0x53dbd7f286a3f8f8, 0x16cadce74cfc1063,
	0x005c19bdfa52c6dd, 0x68868f5d64d46ad3, 0x3a9d512ccf1e186a, 0x367e62c2385660ae,
	0xe359e7ea77dcb1d7, 0x526c0773749abe6e, 0x735ae5f9d09f734b, 0x493fc7cc8a558ba8,
	0xb0b9c1533041ab45, 0x321958ba470a59bd, 0x852db00b5f46c393, 0x91209b2bd336b0e5,
	0x6e604f7d659ef19f, 0xb99a8ae2782ccb24, 0xccf52ab6c814c4c7, 0x4727d9afbe11727b,
	0x7e950d0c0121b34d, 0x756f435670ad471f, 0xf5add442615a6849, 0x4e87e09980b9957a,
	0x2acfa1df50aee355, 0xd898263afd2fd556, 0xc8f4924dd80c8fd6, 0xcf99ca3d754a173a,
	0xfe477bacaf91bf3c, 0xed5371f6d690c12d, 0x831a5c285e687094, 0xc5d3c90a3708a0a4,
	0x0f7f903717d06580, 0x19f9bb13b8fdf27f, 0xb1bd6f1b4d502843, 0x1c761ba38fff4012,
	0x0d1530c4e2e21f3b, 0x8943ce69a7372c8a, 0xe5184e11feb5ce66, 0x618bdb80bd736621,
	0x7d29bad68b574d0b, 0x81bb613e25e6fe5b, 0x071c9c10bc07913f, 0xc7beeb7909ac2d97,
	0xc3e58d353bc5d757, 0xeb017892f38f61e8, 0xd4effb9c9b1cc21a, 0x99727d26f494f7ab,
	0xa3e063a2956b3e03, 0x9d4a8b9a4aa09c30, 0x3f6ab7d500090fb4, 0x9cc0f2a057268ac0,
	0x3dee9d2dedbf42d1, 0x330f49c87960a972, 0xc6b2720287421b41, 0x0ac59ec07c00369c,
	0xef4eac49cb353425, 0xf450244eef0129d8, 0x8acc46e5caf4deb6, 0x2ffeab63989263f7,
	0x8f7cb9fe5d7a4578, 0x5bd8f7644e634635, 0x427a7315bf2dc900, 0x17d0c4aa2125261c,
	0x3992486c93518e50, 0xb4cbfee0a2d7d4c3, 0x7c75d6202c5ddd8d, 0xdbc295d8e35b6c61,
	0x60b369d302032b19, 0xce42685fdce44132, 0x06f3ddb9ddf65610, 0x8ea4d21db5e148f0,
	0x20b0fce62fcd496f, 0x2c1b912358b0ee31, 0xb28317b818f5a308, 0xa89c1e189ca6d2cf,
	0x0c6b18576aaadbc8, 0xb65deaa91299fae3, 0xfb2b794b7f1027e7, 0x04e4317f443b5beb,
	0x4b852d325939d0a6, 0xd5ae6beefb207ffc, 0x309682b281c7d374, 0xbae309a194c3b475,
	0x8cc3f97b13b49f05, 0x98a9422ff8293967, 0x244b16b01076ff7c, 0xf8bf571c663d67ee,
	0x1f0d6758eee30da1, 0xc9b611d97adeb9b7, 0xb7afd5887b6c57a2, 0x6290ae846b984fe1,
	0x94df4cdeacc1a5fd, 0x058a5bd1c5483aff, 0x63166cc142ba3c37, 0x8db8526eb2f76f40,
	0xe10880036f0d6d4e, 0x9e0523c9971d311d, 0x45ec2824cc7cd691, 0x575b8359e62382c9,
	0xfa9e400dc4889995, 0xd1823ecb45721568, 0xdafd983b8206082f, 0xaa7d29082386a8cb,
	0x269fcd4403b87588, 0x1b91f5f728bdd1e0, 0xe4669f39040201f6, 0x7a1d7c218cf04ade,
	0x65623c29d79ce5ce, 0x2368449096c00bb1, 0xab9bf1879da503ba, 0xbc23ecb1a458058e,
	0x9a58df01bb401ecc, 0xa070e868a85f143d, 0x4ff188307df2239e, 0x14d565b41a641183,
	0xee13337452701602, 0x950e3dcf3f285e09, 0x59930254b9c80953, 0x3bf299408930da6d,
	0xa955943f53691387, 0xa15edecaa9cb8784, 0x29142127352be9a0, 0x76f0371fff4e7afb,
	0x0239f450274f2228, 0xbb073af01d5e868b, 0xbfc80571c10e96c1, 0xd267088568222e23,
	0x9671a3d48e80b5b0, 0x55b5d38ae193bb81, 0x693ae2d0a18b04b8, 0x5c48b4ecadd5335f,
	0xfd743b194916a1ca, 0x2577018134be98c4, 0xe77987e83c54a4ad, 0x28e11014da33e1b9,
	0x270cc59e226aa213, 0x71495f756d1a5f60, 0x9be853fb60afef77, 0xadc786a7f7443dbf,
	0x0904456173b29a82, 0x58bc7a66c232bd5e, 0xf306558c673ac8b2, 0x41f639c6b6c9772a,
	0x216defe99fda35da, 0x11640cc71c7be615, 0x93c43694565c5527, 0xea038e6246777839,
	0xf9abf3ce5a3e2469, 0x741e768d0fd312d2, 0x0144b883ced652c6, 0xc20b5a5ba33f8552,
	0x1ae69633c3435a9d, 0x97a28ca4088cfdec, 0x8824a43c1e96f420, 0x37612fa66eeea746,
	0x6b4cb165f9cf0e5a, 0x43aa1c06a0abfb4a, 0x7f4dc26ff162796b, 0x6cbacc8e54ed9b0f,
	0xa6b7ffefd2bb253e, 0x2e25bc95b0a29d4f, 0x86d6a58bdef1388c, 0xded74ac576b6f054,
	0x8030bdbc2b45805d, 0x3c81af70e94d9289, 0x3eff6dda9e3100db, 0xb38dc39fdfcc8847,
	0x123885528d17b87e, 0xf2da0ed240b1b642, 0x44cefadcd54bf9a9, 0x1312200e433c7ee6,
	0x9ffcc84f3a78c748, 0xf0cd1f72248576bb, 0xec6974053638cfe4, 0x2ba7b67c0cec4e4c,
	0xac2f4df3e5ce32ed, 0xcb33d14326ea4c11, 0xa4e9044cc77e58bc, 0x5f513293d934fcef,
	0x5dc9645506e55444, 0x50de418f317de40a, 0x388cb31a69dde259, 0x2db4a83455820a86,
	0x9010a91e84711ae9, 0x4df7f0b7b1498371, 0xd62a2eabc0977179, 0x22fac097aa8d5c0e,
}

var t3 = [...]uint64{
	0xf49fcc2ff1daf39b, 0x487fd5c66ff29281, 0xe8a30667fcdca83f, 0x2c9b4be3d2fcce63,
	0xda3ff74b93fbbbc2, 0x2fa165d2fe70ba66, 0xa103e279970e93d4, 0xbecdec77b0e45e71,
	0xcfb41e723985e497, 0xb70aaa025ef75017, 0xd42309f03840b8e0, 0x8efc1ad035898579,
	0x96c6920be2b2abc5, 0x66af4163375a9172, 0x2174abdcca7127fb, 0xb33ccea64a72ff41,
	0xf04a4933083066a5, 0x8d970acdd7289af5, 0x8f96e8e031c8c25e, 0xf3fec02276875d47,
	0xec7bf310056190dd, 0xf5adb0aebb0f1491, 0x9b50f8850fd58892, 0x4975488358b74de8,
	0xa3354ff691531c61, 0x0702bbe481d2c6ee, 0x89fb24057deded98, 0xac3075138596e902,
	0x1d2d3580172772ed, 0xeb738fc28e6bc30d, 0x5854ef8f63044326, 0x9e5c52325add3bbe,
	0x90aa53cf325c4623, 0xc1d24d51349dd067, 0x2051cfeea69ea624, 0x13220f0a862e7e4f,
	0xce39399404e04864, 0xd9c42ca47086fcb7, 0x685ad2238a03e7cc, 0x066484b2ab2ff1db,
	0xfe9d5d70efbf79ec, 0x5b13b9dd9c481854, 0x15f0d475ed1509ad, 0x0bebcd060ec79851,
	0xd58c6791183ab7f8, 0xd1187c5052f3eee4, 0xc95d1192e54e82ff, 0x86eea14cb9ac6ca2,
	0x3485beb153677d5d, 0xdd191d781f8c492a, 0xf60866baa784ebf9, 0x518f643ba2d08c74,
	0x8852e956e1087c22, 0xa768cb8dc410ae8d, 0x38047726bfec8e1a, 0xa67738b4cd3b45aa,
	0xad16691cec0dde19, 0xc6d4319380462e07, 0xc5a5876d0ba61938, 0x16b9fa1fa58fd840,
	0x188ab1173ca74f18, 0xabda2f98c99c021f, 0x3e0580ab134ae816, 0x5f3b05b773645abb,
	0x2501a2be5575f2f6, 0x1b2f74004e7e8ba9, 0x1cd7580371e8d953, 0x7f6ed89562764e30,
	0xb15926ff596f003d, 0x9f65293da8c5d6b9, 0x6ecef04dd690f84c, 0x4782275fff33af88,
	0xe41433083f820801, 0xfd0dfe409a1af9b5, 0x4325a3342cdb396b, 0x8ae77e62b301b252,
	0xc36f9e9f6655615a, 0x85455a2d92d32c09, 0xf2c7dea949477485, 0x63cfb4c133a39eba,
	0x83b040cc6ebc5462, 0x3b9454c8fdb326b0, 0x56f56a9e87ffd78c, 0x2dc2940d99f42bc6,
	0x98f7df096b096e2d, 0x19a6e01e3ad852bf, 0x42a99ccbdbd4b40b, 0xa59998af45e9c559,
	0x366295e807d93186, 0x6b48181bfaa1f773, 0x1fec57e2157a0a1d, 0x4667446af6201ad5,
	0xe615ebcacfb0f075, 0xb8f31f4f68290778, 0x22713ed6ce22d11e, 0x3057c1a72ec3c93b,
	0xcb46acc37c3f1f2f, 0xdbb893fd02aaf50e, 0x331fd92e600b9fcf, 0xa498f96148ea3ad6,
	0xa8d8426e8b6a83ea, 0xa089b274b7735cdc, 0x87f6b3731e524a11, 0x118808e5cbc96749,
	0x9906e4c7b19bd394, 0xafed7f7e9b24a20c, 0x6509eadeeb3644a7, 0x6c1ef1d3e8ef0ede,
	0xb9c97d43e9798fb4, 0xa2f2d784740c28a3, 0x7b8496476197566f, 0x7a5be3e6b65f069d,
	0xf96330ed78be6f10, 0xeee60de77a076a15, 0x2b4bee4aa08b9bd0, 0x6a56a63ec7b8894e,
	0x02121359ba34fef4, 0x4cbf99f8283703fc, 0x398071350caf30c8, 0xd0a77a89f017687a,
	0xf1c1a9eb9e423569, 0x8c7976282dee8199, 0x5d1737a5dd1f7abd, 0x4f53433c09a9fa80,
	0xfa8b0c53df7ca1d9, 0x3fd9dcbc886ccb77, 0xc040917ca91b4720, 0x7dd00142f9d1dcdf,
	0x8476fc1d4f387b58, 0x23f8e7c5f3316503, 0x032a2244e7e37339, 0x5c87a5d750f5a74b,
	0x082b4cc43698992e, 0xdf917becb858f63c, 0x3270b8fc5bf86dda, 0x10ae72bb29b5dd76,
	0x576ac94e7700362b, 0x1ad112dac61efb8f, 0x691bc30ec5faa427, 0xff246311cc327143,
	0x3142368e30e53206, 0x71380e31e02ca396, 0x958d5c960aad76f1, 0xf8d6f430c16da536,
	0xc8ffd13f1be7e1d2, 0x7578ae66004ddbe1, 0x05833f01067be646, 0xbb34b5ad3bfe586d,
	0x095f34c9a12b97f0, 0x247ab64525d60ca8, 0xdcdbc6f3017477d1, 0x4a2e14d4decad24d,
	0xbdb5e6d9be0a1eeb, 0x2a7e70f7794301ab, 0xdef42d8a270540fd, 0x01078ec0a34c22c1,
	0xe5de511af4c16387, 0x7ebb3a52bd9a330a, 0x77697857aa7d6435, 0x004e831603ae4c32,
	0xe7a21020ad78e312, 0x9d41a70c6ab420f2, 0x28e06c18ea1141e6, 0xd2b28cbd984f6b28,
	0x26b75f6c446e9d83, 0xba47568c4d418d7f, 0xd80badbfe6183d8e, 0x0e206d7f5f166044,
	0xe258a43911cbca3e, 0x723a1746b21dc0bc, 0xc7caa854f5d7cdd3, 0x7cac32883d261d9c,
	0x7690c26423ba942c, 0x17e55524478042b8, 0xe0be477656a2389f, 0x4d289b5e67ab2da0,
	0x44862b9c8fbbfd31, 0xb47cc8049d141365, 0x822c1b362b91c793, 0x4eb14655fb13dfd8,
	0x1ecbba0714e2a97b, 0x6143459d5cde5f14, 0x53a8fbf1d5f0ac89, 0x97ea04d81c5e5b00,
	0x622181a8d4fdb3f3, 0xe9bcd341572a1208, 0x1411258643cce58a, 0x9144c5fea4c6e0a4,
	0x0d33d06565cf620f, 0x54a48d489f219ca1, 0xc43e5eac6d63c821, 0xa9728b3a72770daf,
	0xd7934e7b20df87ef, 0xe35503b61a3e86e5, 0xcae321fbc819d504, 0x129a50b3ac60bfa6,
	0xcd5e68ea7e9fb6c3, 0xb01c90199483b1c7, 0x3de93cd5c295376c, 0xaed52edf2ab9ad13,
	0x2e60f512c0a07884, 0xbc3d86a3e36210c9, 0x35269d9b163951ce, 0x0c7d6e2ad0cdb5fa,
	0x59e86297d87f5733, 0x298ef221898db0e7, 0x55000029d1a5aa7e, 0x8bc08ae1b5061b45,
	0xc2c31c2b6c92703a, 0x94cc596baf25ef42, 0x0a1d73db22540456, 0x04b6a0f9d9c4179a,
	0xeffdafa2ae3d3c60, 0xf7c8075bb49496c4, 0x9cc5c7141d1cd4e3, 0x78bd1638218e5534,
	0xb2f11568f850246a, 0xedfabcfa9502bc29, 0x796ce5f2da23051b, 0xaae128b0dc93537c,
	0x3a493da0ee4b29ae, 0xb5df6b2c416895d7, 0xfcabbd25122d7f37, 0x70810b58105dc4b1,
	0xe10fdd37f7882a90, 0x524dcab5518a3f5c, 0x3c9e85878451255b, 0x4029828119bd34e2,
	0x74a05b6f5d3ceccb, 0xb610021542e13eca, 0x0ff979d12f59e2ac, 0x6037da27e4f9cc50,
	0x5e92975a0df1847d, 0xd66de190d3e623fe, 0x5032d6b87b568048, 0x9a36b7ce8235216e,
	0x80272a7a24f64b4a, 0x93efed8b8c6916f7, 0x37ddbff44cce1555, 0x4b95db5d4b99bd25,
	0x92d3fda169812fc0, 0xfb1a4a9a90660bb6, 0x730c196946a4b9b2, 0x81e289aa7f49da68,
	0x64669a0f83b1a05f, 0x27b3ff7d9644f48b, 0xcc6b615c8db675b3, 0x674f20b9bcebbe95,
	0x6f31238275655982, 0x5ae488713e45cf05, 0xbf619f9954c21157, 0xeabac46040a8eae9,
	0x454c6fe9f2c0c1cd, 0x419cf6496412691c, 0xd3dc3bef265b0f70, 0x6d0e60f5c3578a9e,
}

var t4 = [...]uint64{
	0x5b0e608526323c55, 0x1a46c1a9fa1b59f5, 0xa9e245a17c4c8ffa, 0x65ca5159db2955d7,
	0x05db0a76ce35afc2, 0x81eac77ea9113d45, 0x528ef88ab6ac0a0d, 0xa09ea253597be3ff,
	0x430ddfb3ac48cd56, 0xc4b3a67af45ce46f, 0x4ececfd8fbe2d05e, 0x3ef56f10b39935f0,
	0x0b22d6829cd619c6, 0x17fd460a74df2069, 0x6cf8cc8e8510ed40, 0xd6c824bf3a6ecaa7,
	0x61243d581a817049, 0x048bacb6bbc163a2, 0xd9a38ac27d44cc32, 0x7fddff5baaf410ab,
	0xad6d495aa804824b, 0xe1a6a74f2d8c9f94, 0xd4f7851235dee8e3, 0xfd4b7f886540d893,
	0x247c20042aa4bfda, 0x096ea1c517d1327c, 0xd56966b4361a6685, 0x277da5c31221057d,
	0x94d59893a43acff7, 0x64f0c51ccdc02281, 0x3d33bcc4ff6189db, 0xe005cb184ce66af1,
	0xff5ccd1d1db99bea, 0xb0b854a7fe42980f, 0x7bd46a6a718d4b9f, 0xd10fa8cc22a5fd8c,
	0xd31484952be4bd31, 0xc7fa975fcb243847, 0x4886ed1e5846c407, 0x28cddb791eb70b04,
	0xc2b00be2f573417f, 0x5c9590452180f877, 0x7a6bddfff370eb00, 0xce509e38d6d9d6a4,
	0xebeb0f00647fa702, 0x1dcc06cf76606f06, 0xe4d9f28ba286ff0a, 0xd85a305dc918c262,
	0x475b1d8732225f54, 0x2d4fb51668ccb5fe, 0xa679b9d9d72bba20, 0x53841c0d912d43a5,
	0x3b7eaa48bf12a4e8, 0x781e0e47f22f1ddf, 0xeff20ce60ab50973, 0x20d261d19dffb742,
	0x16a12b03062a2e39, 0x1960eb2239650495, 0x251c16fed50eb8b8, 0x9ac0c330f826016e,
	0xed152665953e7671, 0x02d63194a6369570, 0x5074f08394b1c987, 0x70ba598c90b25ce1,
	0x794a15810b9742f6, 0x0d5925e9fcaf8c6c, 0x3067716cd868744e, 0x910ab077e8d7731b,
	0x6a61bbdb5ac42f61, 0x93513efbf0851567, 0xf494724b9e83e9d5, 0xe887e1985c09648d,
	0x34b1d3c675370cfd, 0xdc35e433bc0d255d, 0xd0aab84234131be0, 0x08042a50b48b7eaf,
	0x9997c4ee44a3ab35, 0x829a7b49201799d0, 0x263b8307b7c54441, 0x752f95f4fd6a6ca6,
	0x927217402c08c6e5, 0x2a8ab754a795d9ee, 0xa442f7552f72943d, 0x2c31334e19781208,
	0x4fa98d7ceaee6291, 0x55c3862f665db309, 0xbd0610175d53b1f3, 0x46fe6cb840413f27,
	0x3fe03792df0cfa59, 0xcfe700372eb85e8f, 0xa7be29e7adbce118, 0xe544ee5cde8431dd,
	0x8a781b1b41f1873e, 0xa5c94c78a0d2f0e7, 0x39412e2877b60728, 0xa1265ef3afc9a62c,
	0xbcc2770c6a2506c5, 0x3ab66dd5dce1ce12, 0xe65499d04a675b37, 0x7d8f523481bfd216,
	0x0f6f64fcec15f389, 0x74efbe618b5b13c8, 0xacdc82b714273e1d, 0xdd40bfe003199d17,
	0x37e99257e7e061f8, 0xfa52626904775aaa, 0x8bbbf63a463d56f9, 0xf0013f1543a26e64,
	0xa8307e9f879ec898, 0xcc4c27a4150177cc, 0x1b432f2cca1d3348, 0xde1d1f8f9f6fa013,
	0x606602a047a7ddd6, 0xd237ab64cc1cb2c7, 0x9b938e7225fcd1d3, 0xec4e03708e0ff476,
	0xfeb2fbda3d03c12d, 0xae0bced2ee43889a, 0x22cb8923ebfb4f43, 0x69360d013cf7396d,
	0x855e3602d2d4e022, 0x073805bad01f784c, 0x33e17a133852f546, 0xdf4874058ac7b638,
	0xba92b29c678aa14a, 0x0ce89fc76cfaadcd, 0x5f9d4e0908339e34, 0xf1afe9291f5923b9,
	0x6e3480f60f4a265f, 0xeebf3a2ab29b841c, 0xe21938a88f91b4ad, 0x57dfeff845c6d3c3,
	0x2f006b0bf62caaf2, 0x62f479ef6f75ee78, 0x11a55ad41c8916a9, 0xf229d29084fed453,
	0x42f1c27b16b000e6, 0x2b1f76749823c074, 0x4b76eca3c2745360, 0x8c98f463b91691bd,
	0x14bcc93cf1ade66a, 0x8885213e6d458397, 0x8e177df0274d4711, 0xb49b73b5503f2951,
	0x10168168c3f96b6b, 0x0e3d963b63cab0ae, 0x8dfc4b5655a1db14, 0xf789f1356e14de5c,
	0x683e68af4e51dac1, 0xc9a84f9d8d4b0fd9, 0x3691e03f52a0f9d1, 0x5ed86e46e1878e80,
	0x3c711a0e99d07150, 0x5a0865b20c4e9310, 0x56fbfc1fe4f0682e, 0xea8d5de3105edf9b,
	0x71abfdb12379187a, 0x2eb99de1bee77b9c, 0x21ecc0ea33cf4523, 0x59a4d7521805c7a1,
	0x3896f5eb56ae7c72, 0xaa638f3db18f75dc, 0x9f39358dabe9808e, 0xb7defa91c00b72ac,
	0x6b5541fd62492d92, 0x6dc6dee8f92e4d5b, 0x353f57abc4beea7e, 0x735769d6da5690ce,
	0x0a234aa642391484, 0xf6f9508028f80d9d, 0xb8e319a27ab3f215, 0x31ad9c1151341a4d,
	0x773c22a57bef5805, 0x45c7561a07968633, 0xf913da9e249dbe36, 0xda652d9b78a64c68,
	0x4c27a97f3bc334ef, 0x76621220e66b17f4, 0x967743899acd7d0b, 0xf3ee5bcae0ed6782,
	0x409f753600c879fc, 0x06d09a39b5926db6, 0x6f83aeb0317ac588, 0x01e6ca4a86381f21,
	0x66ff3462d19f3025, 0x72207c24ddfd3bfb, 0x4af6b6d3e2ece2eb, 0x9c994dbec7ea08de,
	0x49ace597b09a8bc4, 0xb38c4766cf0797ba, 0x131b9373c57c2a75, 0xb1822cce61931e58,
	0x9d7555b909ba1c0c, 0x127fafdd937d11d2, 0x29da3badc66d92e4, 0xa2c1d57154c2ecbc,
	0x58c5134d82f6fe24, 0x1c3ae3515b62274f, 0xe907c82e01cb8126, 0xf8ed091913e37fcb,
	0x3249d8f9c80046c9, 0x80cf9bede388fb63, 0x1881539a116cf19e, 0x5103f3f76bd52457,
	0x15b7e6f5ae47f7a8, 0xdbd7c6ded47e9ccf, 0x44e55c410228bb1a, 0xb647d4255edb4e99,
	0x5d11882bb8aafc30, 0xf5098bbb29d3212a, 0x8fb5ea14e90296b3, 0x677b942157dd025a,
	0xfb58e7c0a390acb5, 0x89d3674c83bd4a01, 0x9e2da4df4bf3b93b, 0xfcc41e328cab4829,
	0x03f38c96ba582c52, 0xcad1bdbd7fd85db2, 0xbbb442c16082ae83, 0xb95fe86ba5da9ab0,
	0xb22e04673771a93f, 0x845358c9493152d8, 0xbe2a488697b4541e, 0x95a2dc2dd38e6966,
	0xc02c11ac923c852b, 0x2388b1990df2a87b, 0x7c8008fa1b4f37be, 0x1f70d0c84d54e503,
	0x5490adec7ece57d4, 0x002b3c27d9063a3a, 0x7eaea3848030a2bf, 0xc602326ded2003c0,
	0x83a7287d69a94086, 0xc57a5fcb30f57a8a, 0xb56844e479ebe779, 0xa373b40f05dcbce9,
	0xd71a786e88570ee2, 0x879cbacdbde8f6a0, 0x976ad1bcc164a32f, 0xab21e25e9666d78b,
	0x901063aae5e5c33c, 0x9818b34448698d90, 0xe36487ae3e1e8abb, 0xafbdf931893bdcb4,
	0x6345a0dc5fbbd519, 0x8628fe269b9465ca, 0x1e5d01603f9c51ec, 0x4de44006a15049b7,
	0xbf6c70e5f776cbb1, 0x411218f2ef552bed, 0xcb0c0708705a36a3, 0xe74d14754f986044,
	0xcd56d9430ea8280e, 0xc12591d7535f5065, 0xc83223f1720aef96, 0xc3a0396f7363a51f,
}

type TigerHasher struct {
	/* State of the hasher */
	state 		[3]uint64
	count 		[2]uint32
	buffer 		[64]uint8
	opad		uint8
}

const HASH_SIZE_TIGER = 24

func round(a *uint64, b *uint64, c *uint64, x uint64, mul uint8){
	*c ^= x
	*a -= t1[(*c)&0xff] ^ t2[((*c)>>16)&0xff] ^ t3[((*c)>>32)&0xff] ^ t4[((*c)>>48)&0xff]
	*b += t4[((*c)>>8)&0xff] ^ t3[((*c)>>24)&0xff] ^ t2[((*c)>>40)&0xff] ^ t1[((*c)>>56)&0xff]
	*b *= uint64(mul)
}



func keySchedule(x []uint64) {
	x[0] -= x[7] ^ 0xa5a5a5a5a5a5a5a5
	x[1] ^= x[0]
	x[2] += x[1]
	x[3] -= x[2] ^ ((^x[1]) << 19)
	x[4] ^= x[3]
	x[5] += x[4]
	x[6] -= x[5] ^ ((^x[4]) >> 23)
	x[7] ^= x[6]
	x[0] += x[7]
	x[1] -= x[0] ^ ((^x[7]) << 19)
	x[2] ^= x[1]
	x[3] += x[2]
	x[4] -= x[3] ^ ((^x[2]) >> 23)
	x[5] ^= x[4]
	x[6] += x[5]
	x[7] -= x[6] ^ 0x0123456789abcdef
}

func pass(aa *uint64, bb *uint64, cc *uint64, x []uint64, mul uint8) {
	a, b, c := *aa, *bb, *cc
	round(&a, &b, &c, x[0], mul)
	round(&b, &c, &a, x[1], mul)
	round(&c, &a, &b, x[2], mul)
	round(&a, &b, &c, x[3], mul)
	round(&b, &c, &a, x[4], mul)
	round(&c, &a, &b, x[5], mul)
	round(&a, &b, &c, x[6], mul)
	round(&b, &c, &a, x[7], mul)
	*aa, *bb, *cc = a, b, c
}

/* Tiger basic transformation. Transforms state based on block */
func (hasher *TigerHasher) Transform(block []uint8) {
	var a, b, c = hasher.state[0], hasher.state[1], hasher.state[2]
	//var x []uint64 = *(*[]uint64)(unsafe.Pointer(&block))
	var x []uint64 = Decode64(block)

	/* Round 1 */
	//var mul uint8 = 5
	//round(&a, &b, &c, x[0], mul)
	//round(&b, &c, &a, x[1], mul)
	//round(&c, &a, &b, x[2], mul)
	//round(&a, &b, &c, x[3], mul)
	//round(&b, &c, &a, x[4], mul)
	//round(&c, &a, &b, x[5], mul)
	//round(&a, &b, &c, x[6], mul)
	//round(&b, &c, &a, x[7], mul)
	pass(&a, &b, &c, x, 5)
	keySchedule(x)

	/* Round 2 */
	//mul = 7
	//round(&c, &a, &b, x[0], mul)
	//round(&a, &b, &c, x[1], mul)
	//round(&b, &c, &a, x[2], mul)
	//round(&c, &a, &b, x[3], mul)
	//round(&a, &b, &c, x[4], mul)
	//round(&b, &c, &a, x[5], mul)
	//round(&a, &b, &c, x[6], mul)
	//round(&b, &c, &a, x[7], mul)
	pass(&c, &a, &b, x, 7)
	keySchedule(x)

	/* Round 3 */
	pass(&b, &c, &a, x, 9)
	//mul = 9
	//round(&b, &c, &a, x[0], mul)
	//round(&c, &a, &b, x[1], mul)
	//round(&a, &b, &c, x[2], mul)
	//round(&b, &c, &a, x[3], mul)
	//round(&c, &a, &b, x[4], mul)
	//round(&a, &b, &c, x[5], mul)
	//round(&b, &c, &a, x[6], mul)
	//round(&c, &a, &b, x[7], mul)

	hasher.state[0] ^= a
	hasher.state[1] = b - hasher.state[1]
	hasher.state[2] += c
}

/* Tiger change status-values in struct */
func (hasher *TigerHasher) ChangeStatus(state []uint64, count []uint32){
	copy(hasher.state[:], state[:])
	copy(hasher.count[:], count[:])
}

/* Tiger Update status */
func (hasher *TigerHasher) Update(data []uint8) {
	var i, index, partLen uint32
	inputLen := uint32(len(data))

	/* Compute number of bytes mod 64 */
	index = (hasher.count[0] >> 3) & 0x3F

	hasher.count[0] += inputLen << 3
	/* Update number of bits */
	if hasher.count[0] < (inputLen << 3) {
		hasher.count[1]++
	}
	hasher.count[1] += inputLen >> 29

	partLen = 64 - index

	/* Transform as many times as possible. */
	if inputLen >= partLen {
		copy(hasher.buffer[index:], data[0:partLen])
		hasher.Transform(hasher.buffer[:])
		for i = partLen; i + 63 < inputLen; i += 64 {
			hasher.Transform(data[i:])
		}
		index = 0
	} else {
		i = 0
	}

	/* Buffer remaining input */
	copy(hasher.buffer[index:], data[i:])
}

func (hasher *TigerHasher) Final() []uint8 {
	var index uint32
	var digest [HASH_SIZE_TIGER]uint8
	bits := Encode(hasher.count[0:2])

	/* Pad out to 56 mod 64. */
	index = (hasher.count[0] >> 3) & 0x3f
	var padding = bytes.Repeat([]uint8{0}, int(56 - (index + 1) % 64 + 1))
	padding[0] = hasher.opad
	hasher.Update(padding)

	///* Append length (before padding) */
	hasher.Update(bits[0:8])
	for i := 0; i < 8; i++ {
		digest[i] = uint8(hasher.state[0] >> (8 * i))
		digest[i+8] = uint8(hasher.state[1] >> (8 * i))
		digest[i+16] = uint8(hasher.state[2] >> (8 * i))
	}
	return digest[:]
}

func (hasher *TigerHasher) Reset() {
	hasher.state[0] = 0x0123456789abcdef
	hasher.state[1] = 0xFEDCBA9876543210
	hasher.state[2] = 0xF096A5B4C3B2E187
	hasher.count[0] = 0
	hasher.count[1] = 0
}

func (hasher TigerHasher) GetPad() uint8 {
	return hasher.opad
}

func (hasher *TigerHasher) GetHash(data []uint8) []uint8 {
	hasher.Update(data)
	digest := hasher.Final()

	hasher.Reset()
	return digest[:]
}

func (hasher TigerHasher) GetHashSize() uint32 {
	return HASH_SIZE_TIGER
}

func (hasher TigerHasher) PrintStatus() {
	fmt.Printf("Hasher:\n")
	fmt.Printf("\t\tstate: %v\n", hasher.state)
	fmt.Printf("\t\tcount: %v\n", hasher.count)
	fmt.Printf("\t\tbuffer: %v\n\n", hasher.buffer)

}

func CreateTigerHasherPrivate(opad uint8) TigerHasher {
	hasher := TigerHasher{opad:opad}
	hasher.Reset()
	return hasher
}

func CreateTigerHasher(opad uint8) Hasher {
	hasher := TigerHasher{opad:opad}
	hasher.Reset()
	return &hasher
}