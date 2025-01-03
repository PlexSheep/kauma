# Changelog

## [0.4.0](https://github.com/PlexSheep/kauma/compare/v0.3.0...v0.4.0) (2024-12-23)


### Features

* **gcm_crack:** magic poly repr ([dde8b1c](https://github.com/PlexSheep/kauma/commit/dde8b1c35eaec67ab094bb7e1756d7bf0eafefee))
* **gcm_crack:** works but wrong ([aad1e21](https://github.com/PlexSheep/kauma/commit/aad1e2135c86f381f98f0102075cd04b135be2da))


### Bug Fixes

* **gcm_crack:** fix magic_p ([5f4387d](https://github.com/PlexSheep/kauma/commit/5f4387d0f077999aa98eac69ab1c65a88fe934b3))
* **gcm_crack:** IT WORKS ([0d983be](https://github.com/PlexSheep/kauma/commit/0d983bead3ff5f76dc91a802a236a3880bf59f85))
* **superpoly:** edf is now sorted ([8d1170c](https://github.com/PlexSheep/kauma/commit/8d1170cc004dffc817e3a7db784a458cddb96156))

## [0.3.0](https://github.com/PlexSheep/kauma/compare/v0.2.0...v0.3.0) (2024-12-23)


### Features

* **ffield:** cmp function for Polynomial ([9192926](https://github.com/PlexSheep/kauma/commit/91929262328d8428d86a712e0ba32cee9a997ff7))
* **ffield:** gfdiv base ([9cd96a7](https://github.com/PlexSheep/kauma/commit/9cd96a767ec8a33baf7c6511a853f4261b4a4484))
* **ffield:** impl pow for FieldElement ([24cfe57](https://github.com/PlexSheep/kauma/commit/24cfe57cb3a03bda272b7d0ff6ea0565c5e7600d))
* **interface:** add a maybe_hex function ([a31f842](https://github.com/PlexSheep/kauma/commit/a31f8424a4c272c04b67be8e4e2c8e75d1fe32ee))
* only use multithreading if there are more challenges than one ([87713c0](https://github.com/PlexSheep/kauma/commit/87713c0748699e2c058369707b147d8c5366bc52))
* **superpoly:** add gfpoly_add action ([bcc3398](https://github.com/PlexSheep/kauma/commit/bcc33984c05838aba9f535daea2cadf514799556))
* **superpoly:** add gfpoly_sort action ([3b7c860](https://github.com/PlexSheep/kauma/commit/3b7c860909360ee12620377b8f79d6ee1c4fab63))
* **superpoly:** add powmod action ([682bc1d](https://github.com/PlexSheep/kauma/commit/682bc1dbac7c149d48416f9810ac05dc3f43a325))
* **superpoly:** add with cutoff ([0cebfb2](https://github.com/PlexSheep/kauma/commit/0cebfb2535b877400f80228cae61174c31a98e5f))
* **superpoly:** basic mul ([5b959ee](https://github.com/PlexSheep/kauma/commit/5b959eee34dfba17a25f9674e6e88c8db9c858bc))
* **superpoly:** broken divmod ([85395e7](https://github.com/PlexSheep/kauma/commit/85395e7caffe208a8546d2d23230a75bd728a6bb))
* **superpoly:** divmod action ([94a154f](https://github.com/PlexSheep/kauma/commit/94a154f185072ec01a042841e967387396bc6886))
* **superpoly:** divmod prototype ([483a0b6](https://github.com/PlexSheep/kauma/commit/483a0b66136eea134c59213fb867069da408ab0a))
* **superpoly:** first gfpoly_diff impl ([010b57f](https://github.com/PlexSheep/kauma/commit/010b57fe41cbc1a896728cc815083855aede981e))
* **superpoly:** first sqrt fails ([e3c8e5f](https://github.com/PlexSheep/kauma/commit/e3c8e5ffc2a215826ab2b10480ae6d635009a6e7))
* **superpoly:** gfdiv ([c03e914](https://github.com/PlexSheep/kauma/commit/c03e91411622870cb7271f290aaf1ad272f54da5))
* **superpoly:** impl add and addassign (and xor, thats the same) ([dce6547](https://github.com/PlexSheep/kauma/commit/dce6547dfa1e15e25eaa308caf2aad77382a5e10))
* **superpoly:** impl ddf ([a3349db](https://github.com/PlexSheep/kauma/commit/a3349dbcd5db5de2d06ff5cb9ca169436759a1b5))
* **superpoly:** impl Debug ([8fe65bc](https://github.com/PlexSheep/kauma/commit/8fe65bcde12580f5fdecd9096a851d8b146b4144))
* **superpoly:** impl edf ([5a8c15b](https://github.com/PlexSheep/kauma/commit/5a8c15b5e9d7c50853219eb82f92afbc27bf131c))
* **superpoly:** impl first gcd ([1b2b74a](https://github.com/PlexSheep/kauma/commit/1b2b74a94d3e27155cd59e70b800d3a0fc1ec28f))
* **superpoly:** impl Ord for superpoly ([025bb61](https://github.com/PlexSheep/kauma/commit/025bb61e223012b6e54e2b7b9121c83e631915b5))
* **superpoly:** impl pow, but incorrectly ([1a7774c](https://github.com/PlexSheep/kauma/commit/1a7774c8cc4509b314cb07b10821af3a92882702))
* **superpoly:** impl powmod ([a806432](https://github.com/PlexSheep/kauma/commit/a806432761875486594130cdf97f894a16d3bc19))
* **superpoly:** impl sff ([3ca085d](https://github.com/PlexSheep/kauma/commit/3ca085dca3b17db51aeabded7926f1e8dbdebe40))
* **superpoly:** impl sqrt ([9e38760](https://github.com/PlexSheep/kauma/commit/9e38760962401f7be21c0c473a41e5a058a3b947))
* **superpoly:** implement Eq ([f69cd28](https://github.com/PlexSheep/kauma/commit/f69cd283585017554f0ae8c29a98645fa0a955ea))
* **superpoly:** initial struct ([7516f75](https://github.com/PlexSheep/kauma/commit/7516f75197b2e5eb0274f5f67e5b4031c942cec8))
* **superpoly:** monic works for the given ([15565b8](https://github.com/PlexSheep/kauma/commit/15565b82778a7eafe4e84effc18104cd82c3ed0f))
* **superpoly:** structure done for add ([650e582](https://github.com/PlexSheep/kauma/commit/650e5820897282c36b4a20d2b912954ae06a819a))
* **superpoly:** structure for gfpoly_pow ([8e8ab7c](https://github.com/PlexSheep/kauma/commit/8e8ab7c90be551dc3048bccc5d8d509c8e9511f8))
* **superpoly:** working first edf ([aaca879](https://github.com/PlexSheep/kauma/commit/aaca87948a70df75d2e6590b3418995840fd7b6f))


### Bug Fixes

* bad formatting for the cpu num log ([74093ce](https://github.com/PlexSheep/kauma/commit/74093ceb5c16572cf56ebd6900c3b6bcf1931787))
* **ffield:** gfdiv converted semantic too often and used wrong function ([849db5b](https://github.com/PlexSheep/kauma/commit/849db5b8445d19e197b08772cac415ee16deee40))
* gcd had wrong json key ([3f0e211](https://github.com/PlexSheep/kauma/commit/3f0e211fad98348170072d1fb95a709ef5be5eaa))
* incorrect json format in one file ([607303f](https://github.com/PlexSheep/kauma/commit/607303f4af26465f2db2911951c3248c8072a60a))
* **superpoly:** addition takes length of coefficients into account now ([992f430](https://github.com/PlexSheep/kauma/commit/992f4303f413cf85c7b272301aafd34f5b18ead0))
* **superpoly:** all my tests are wrong but I have a feeling ([06ecafb](https://github.com/PlexSheep/kauma/commit/06ecafb87a415c92a0a7577fc97170daaf1d5dfd))
* **superpoly:** always modulo after powmod ([79508e5](https://github.com/PlexSheep/kauma/commit/79508e5a39ef02381ae98e26ce3b9d02e47720cc))
* **superpoly:** change the semantic back when serializing ([e73f9b9](https://github.com/PlexSheep/kauma/commit/e73f9b925201c8e1fc77d6b16d10a99cfe845f97))
* **superpoly:** cover more edgecases in powmod ([80fb0a4](https://github.com/PlexSheep/kauma/commit/80fb0a4aea3933f330736173a679e9a27431fb8f))
* **superpoly:** cover the identity operation ([16de7a1](https://github.com/PlexSheep/kauma/commit/16de7a1d01ec489026aaf17a69c88f7b907a3cae))
* **superpoly:** deg and one were not correct ([c15bb30](https://github.com/PlexSheep/kauma/commit/c15bb30d29035bdd2fd211af5486ecade8c92ac3))
* **superpoly:** degree was calculated wrongly ([2ed429a](https://github.com/PlexSheep/kauma/commit/2ed429af41a375126dbed4b6bc39fad0f8c08169))
* **superpoly:** did not add all coefficients together ([d807bfc](https://github.com/PlexSheep/kauma/commit/d807bfc02a4b841a856f9fe751d08f5d23e03b98))
* **superpoly:** divmod now works ([033a279](https://github.com/PlexSheep/kauma/commit/033a279bc4a1a1da1108b79a713c7a722ad982ce))
* **superpoly:** I think normalize causes bugs? ([ba5698e](https://github.com/PlexSheep/kauma/commit/ba5698e764e1d3213f8e8505fd53c887c6f31140))
* **superpoly:** imports and concrete type in a test ([dbd5ddb](https://github.com/PlexSheep/kauma/commit/dbd5ddb0bfff8025c5109199705d06258dfcca86))
* **superpoly:** just simply remove the zeros at the end of superpolys ([a3126df](https://github.com/PlexSheep/kauma/commit/a3126df0a3226a063d82bd5e89bd516247d666ee))
* **superpoly:** make gfpoly_mul almost correct ([2fef758](https://github.com/PlexSheep/kauma/commit/2fef758225d2a3e5e8f79281a027dbfd5d9d4175))
* **superpoly:** make multiplication work ([21a0443](https://github.com/PlexSheep/kauma/commit/21a0443977820d44a07f9bd683745eaec290922b))
* **superpoly:** make pow work ([c6951ca](https://github.com/PlexSheep/kauma/commit/c6951caa2af7f45050fd119b06b642486eceaae5))
* **superpoly:** maybe fix Ord, this is getting confusing again ([4d95f99](https://github.com/PlexSheep/kauma/commit/4d95f998885ed1157e9ca1c8fd6beeddf1185eaf))
* **superpoly:** normalize down to 0 after operations, to make sure I don't output multiple zero coefficients ([3498c5d](https://github.com/PlexSheep/kauma/commit/3498c5de3f315847f5c1995df05230a4d177d943))
* **superpoly:** Ord was incorrect if degree was the same ([5d7bd04](https://github.com/PlexSheep/kauma/commit/5d7bd044bf869373643e07128663c96f8249fa4c))
* **superpoly:** Ord was wrong in some cases ([658e732](https://github.com/PlexSheep/kauma/commit/658e73259874828b2b668a94d1cd934cae9f6654))
* **superpoly:** Ord works somehow ([c2e649c](https://github.com/PlexSheep/kauma/commit/c2e649c4d2dfac89a3273ee511f7a055b218f9bc))
* **superpoly:** powmod edge case order ([119aa4b](https://github.com/PlexSheep/kauma/commit/119aa4ba7e50f372d5569f2679190ca06a1e6a27))
* **superpoly:** powmod edgecase check was in bad order ([24772c2](https://github.com/PlexSheep/kauma/commit/24772c29bdd8f85c46ca0a95011937c9ed0f6b85))
* **superpoly:** powmod returns zero now if module is one ([5a73bca](https://github.com/PlexSheep/kauma/commit/5a73bcab0e326542cb10608e5bf9293d5b8ab36f))
* **superpoly:** read from wrong key ([35c7b96](https://github.com/PlexSheep/kauma/commit/35c7b96955c54c385e785937910a2c0c484d898f))
* **superpoly:** remove leading zeros ([ac98eb5](https://github.com/PlexSheep/kauma/commit/ac98eb55d04d4db97f606bb72ab9659b6e25f4da))
* **superpoly:** try to make pow work ([7b5c053](https://github.com/PlexSheep/kauma/commit/7b5c0532fe0782f6e8eb9d63ba9ce02bb45b1c90))
* **superpoly:** use the correct key for the response in gfpoly_sort ([a2356dd](https://github.com/PlexSheep/kauma/commit/a2356dd211d40ee963a5512d86da5c9319210075))
* **superpoly:** zero is not empty ([fde5909](https://github.com/PlexSheep/kauma/commit/fde5909af43c8ea83556c6df44f2295700e8425a))

## [0.2.0](https://github.com/PlexSheep/kauma/compare/v0.1.0...v0.2.0) (2024-11-29)


### Features

* **bint:** convert u256 to bytes ([a270c86](https://github.com/PlexSheep/kauma/commit/a270c8697e7eebfe468217d5c2a91fa6b0b53a13))
* **bint:** create easy-bint crate ([7a72202](https://github.com/PlexSheep/kauma/commit/7a722024b8206f1ce78ba3d9e0c01e2a4c4b321c))
* **bint:** more implementation for bint (xor, conversion, accessing parts) ([c9f3210](https://github.com/PlexSheep/kauma/commit/c9f3210c19c2fe7939aacb200a9ba165fe902402))
* **bint:** more trait impls for u256 ([bdc3716](https://github.com/PlexSheep/kauma/commit/bdc37165c3777b4f208a7d0da27bd3296dde3894))
* **bint:** reverse_bits for u256 + doc and debug improvements ([c39483b](https://github.com/PlexSheep/kauma/commit/c39483bf92bfad37975b84ecf4ba874ea31b9c22))
* **bint:** shift left and right by one ([bbae096](https://github.com/PlexSheep/kauma/commit/bbae0964bf25f62cd063ce83883d007f8d2d401d))
* **bint:** swap parts and swap bytes for u256 ([45c4303](https://github.com/PlexSheep/kauma/commit/45c43033f4e98ef54c194ccebd6490171e859616))
* **bint:** u256 displays and order ([b41454a](https://github.com/PlexSheep/kauma/commit/b41454a19485c6fea027e5c5ab314eead02f466c))
* **bint:** u256 with add and shl ([86fad87](https://github.com/PlexSheep/kauma/commit/86fad87ab687d2a5a3385b1767d128572e8c49ea))
* **cipher:** build gcm datatypes and function definitions ([b329608](https://github.com/PlexSheep/kauma/commit/b3296083c147944f3cceed75f8c72a557d7e0ea5))
* **cipher:** ghash ([e7fbe19](https://github.com/PlexSheep/kauma/commit/e7fbe19e0cb3d61fff43fe7ee55f55dac6f7c086))
* **cipher:** implement parts of gcm_encrypt ([f70af0c](https://github.com/PlexSheep/kauma/commit/f70af0c25f31f31cc8f08eea364a056b3a5e2ca3))
* **cipher:** make gcm encrypt and decrypt work ([984effe](https://github.com/PlexSheep/kauma/commit/984effe26c8b2d8083431da85c1825fa84312026))
* **cipher:** make GcmEncrypt action work ([18133f9](https://github.com/PlexSheep/kauma/commit/18133f9379cdd881cccffd3d77ed10781fdec141))
* **cipher:** PrimitiveAlgorithm enum ([1af49e2](https://github.com/PlexSheep/kauma/commit/1af49e2398592a33d4327adde8ecd74c6e5484d3))
* **common:** run with timeout ([8db1e80](https://github.com/PlexSheep/kauma/commit/8db1e800063f34668f696478318f9428b0b75d93))
* **ffield:** acccept gcm semantic polynomials ([6ebce72](https://github.com/PlexSheep/kauma/commit/6ebce72c8032c813c19caaba58adb31894d04f99))
* **ffield:** general gfmul but with bugs ([26345b1](https://github.com/PlexSheep/kauma/commit/26345b190036434bf370f00092d3a3715b3316cb))
* **ffield:** mul any polynom ([dad38a1](https://github.com/PlexSheep/kauma/commit/dad38a157fc5956310f0ac4ffd512c0d498f6c4e))
* **ffield:** poly2block can do gcm sem now ([eb33d5d](https://github.com/PlexSheep/kauma/commit/eb33d5dfaab10c752d29aedee25ab6ead9315d0e))
* **oracle:** guess the last 13 byte for the test ([4e7a2f3](https://github.com/PlexSheep/kauma/commit/4e7a2f3acd8ae0c9c8cfd4883a75dddc161002c8))
* **oracle:** make some requests that don't yet lead anywhere ([a800db6](https://github.com/PlexSheep/kauma/commit/a800db6bd330a1ab3e18db1f872a00ae8d6f1dda))
* **oracle:** verify candidate function ([c9b73bf](https://github.com/PlexSheep/kauma/commit/c9b73bf9142ea95d76fc3fe776e312c3fb20fb53))
* **pad:** pad structure ([7a3cd0c](https://github.com/PlexSheep/kauma/commit/7a3cd0c215c1c307f26add9626fad34a2830dc1b))
* **padsim:** add padding with pkcs7 in a new crate ([4f4969b](https://github.com/PlexSheep/kauma/commit/4f4969b5e146924bbcc5486ca6028035f9bc4361))
* **padsim:** allow printing out an encrypted block ([f400df6](https://github.com/PlexSheep/kauma/commit/f400df6db208d7c890fd42db944367d3f80bc52d))
* **padsim:** encrypt and decrypt with pkcs7 and xor ([9410137](https://github.com/PlexSheep/kauma/commit/9410137eee5524fea6b7b79c38abdef3cee665ad))
* **padsim:** make it an executable ([2b1f0ed](https://github.com/PlexSheep/kauma/commit/2b1f0edbe9d0ff56619f3665c5714a08f10bd2f1))
* **padsim:** server maybe works ([5db304e](https://github.com/PlexSheep/kauma/commit/5db304ecfe1db75946f243204d7b37b63266f714))
* **padsim:** show example q and plaintext when no q was correct ([cb615b5](https://github.com/PlexSheep/kauma/commit/cb615b5b130057904c3e7449e8148ff2961c80fd))


### Bug Fixes

* **cipher:** ghash calculated L badly ([6a54805](https://github.com/PlexSheep/kauma/commit/6a54805f82d358d252dbf7ab4fc7d32023f41504))
* **cipher:** ghash didn't append the modified ciphertext to `all` ([93156ef](https://github.com/PlexSheep/kauma/commit/93156ef42c9cb84e638ca5cc4ceea7578b8c56e9))
* **cipher:** only do the verbose prints if verbose is actually set ([0d118bf](https://github.com/PlexSheep/kauma/commit/0d118bf986ab5de71aa5878803740b5c57c8a85d))
* did not use run_challenges_mt when available ([5b1d67f](https://github.com/PlexSheep/kauma/commit/5b1d67f5c0b5027fce662dbbe20714822af3655c))
* **ffield:** convert back to the requested semantic for gfmul ([037e21e](https://github.com/PlexSheep/kauma/commit/037e21ea5241c6bdac372f95e8bb5331cb816de5))
* **ffield:** convert to the requested semantic, instead of just gcm ([214cf58](https://github.com/PlexSheep/kauma/commit/214cf58a5c6ac2056455644bae3d6e98dfd221f6))
* **oracle:** include 0xff case, which for somereason is the 256th byte ([a5220e0](https://github.com/PlexSheep/kauma/commit/a5220e0d7e9275b2cd6b9a4e27b208ae54b77b06))
* **oracle:** make the padding oracle abuse work ([47d6721](https://github.com/PlexSheep/kauma/commit/47d67211e02717f8ed17133b03769fc6deb59cfe))
* **oracle:** verify function was bad ([5606b86](https://github.com/PlexSheep/kauma/commit/5606b86e384c2337f218a853033715f72b2078f0))
* **padsim:** answers were given in wrong sorting ([707b5ad](https://github.com/PlexSheep/kauma/commit/707b5ad30c75936963969a0b0b649b9e56ca35c8))
* **padsim:** clear answers after evaluation, remove bad assert ([ef4f6f5](https://github.com/PlexSheep/kauma/commit/ef4f6f54cd0fc8946d3363d1d2b4432bf4c44ef6))
* **padsim:** remove unnecessary input length for --encrypt ([2eaac05](https://github.com/PlexSheep/kauma/commit/2eaac05f18d707cdc833fe403751a96d148d1355))
* **padsim:** some logs were not prefixed correctly, print indexes of correct q's ([2c68c00](https://github.com/PlexSheep/kauma/commit/2c68c0077527b5bd21b985fed637e24b7bded960))
* **padsim:** test for lib used wrong signatures ([72e24ec](https://github.com/PlexSheep/kauma/commit/72e24ec13475d59f6ae378ee82d94c120d15bf0c))

## 0.1.0 (2024-10-30)


### Features

* add sd_timeout debug action to check that jobs actually time out ([fe46a71](https://github.com/PlexSheep/kauma/commit/fe46a711c266df58e961913ce2e4fee3a9444adb))
* **block2poly:** implement block2poly action ([93c47d5](https://github.com/PlexSheep/kauma/commit/93c47d57c387b76fbbe7aabc1a48fcc266962bda))
* **c1:** add defining relations for smaller fields ([d13521d](https://github.com/PlexSheep/kauma/commit/d13521d638cc64ae8d32667414a6324e75bbc4c0))
* **c1:** display solution and operation ([63417d9](https://github.com/PlexSheep/kauma/commit/63417d9e501e85d87ba2d50e7bbcd446f8b89461))
* **c1:** first implementation of add and mul ([3c14f92](https://github.com/PlexSheep/kauma/commit/3c14f928a9c92a3336b257338b79a85c94e2de4c))
* **c1:** implement solve ([43a1a14](https://github.com/PlexSheep/kauma/commit/43a1a14b00429d5c5e1d160ea0fa54e695e379ce))
* **c1:** structure for calculating with polynomials on F_2_128 ([4140934](https://github.com/PlexSheep/kauma/commit/41409343e9ff15f8dd2c88f22afe8a5fa970fa03))
* **c1:** try to display a polynom and fail miserably ([6e65d44](https://github.com/PlexSheep/kauma/commit/6e65d44525c82fe34f1490966fc0bd3eb4cd176e))
* **c1:** understand machine repr of polynomails and display it correctly ([0140a64](https://github.com/PlexSheep/kauma/commit/0140a6485432218e32f5ed5a0487448713ae478c))
* **cipher:** add xex action with empty functions ([b83dcbd](https://github.com/PlexSheep/kauma/commit/b83dcbd47d428b08757147ba64fa08824fb5e1d9))
* **cipher:** decryption for sea_128_xex ([a819b50](https://github.com/PlexSheep/kauma/commit/a819b50c117bfcbb38f5fd12b7a76abadd04e987))
* **cipher:** first version of sea_128_xex_encrypt ([72b7ead](https://github.com/PlexSheep/kauma/commit/72b7ead4ea35ee67c1f1cbeb08bb1259b24936c5))
* **cipher:** make sea_128_xex encrypt work for the test ([02292a6](https://github.com/PlexSheep/kauma/commit/02292a6dc8b6fd6cacfc193a41a84ca05fc75f1b))
* **cipher:** sea_128 decrypt but wrong, nopad ([02a78e2](https://github.com/PlexSheep/kauma/commit/02a78e2038b3a12d02cd7c457017509d2c3761f6))
* **cipher:** sea128 encrypt ([50ff66d](https://github.com/PlexSheep/kauma/commit/50ff66dc9a2ca2f22f4df14da704779486dbcb84))
* **cli:** allow inputting actions with args with options instead of a JSON file [#9](https://github.com/PlexSheep/kauma/issues/9) ([b91d606](https://github.com/PlexSheep/kauma/commit/b91d6066e55a1914031d5375fb7fd0e03c1b6104))
* **cli:** CLI with getopts ([afd62cc](https://github.com/PlexSheep/kauma/commit/afd62cc05b5d484d160de5ceeecb26062fc80b19))
* **cli:** dump testcase definition with verbose output ([cc0d215](https://github.com/PlexSheep/kauma/commit/cc0d2157dbe28351b2ed68dbb695fbe80dc4b205))
* **cli:** read from stdin when the first argument is `-` [#8](https://github.com/PlexSheep/kauma/issues/8) ([ecd5a67](https://github.com/PlexSheep/kauma/commit/ecd5a67acd2aacfcb38449dba9661b19730ccc72))
* **common:** add get_bytes_maybe_hex ([87aa22f](https://github.com/PlexSheep/kauma/commit/87aa22feab537c82bb494dc09fd78d6ecdab1b41))
* **common:** add put_bytes and get_bytes for getting and writing bytes to and from json ([6a15555](https://github.com/PlexSheep/kauma/commit/6a155552bfb3bf57bc77a045806b05484d309047))
* **common:** add veprintln function to help with verbose debug prints ([4be7c2c](https://github.com/PlexSheep/kauma/commit/4be7c2cbe1402be9dc1eeb2a59e1e006143c5969))
* **common:** encode and decode bytes to and from hex ([57e19a1](https://github.com/PlexSheep/kauma/commit/57e19a1068c0f6dc9b9614faa41ad07db8605ea3))
* **common:** get bit at index ([11fea74](https://github.com/PlexSheep/kauma/commit/11fea74b0e545e0f0ca0e4de5ec251a170c9ef1f))
* **common:** tag some json value ([17cd0e6](https://github.com/PlexSheep/kauma/commit/17cd0e6a0a391990c5e80c93003f8387f777d387))
* **common:** vec to arr ([767251f](https://github.com/PlexSheep/kauma/commit/767251feb8585bed774aa2e9e72dab9b93cc1bef))
* **example:** solve the first example testcase addsub ([8f9590d](https://github.com/PlexSheep/kauma/commit/8f9590d71dd9085072f7f77795113d3ecdce8b35))
* **ffield:** add gfmul action ([e998611](https://github.com/PlexSheep/kauma/commit/e998611b862daddf27054d31779e84554ba1751e))
* **ffield:** add SD_DisplayPolyBlock action [#7](https://github.com/PlexSheep/kauma/issues/7) ([16ee7d9](https://github.com/PlexSheep/kauma/commit/16ee7d9dc4cff6e2da32be1e3bcd0915ad163de1))
* **ffield:** implement a primitive multiplication that only works with y=alpha ([e249b6c](https://github.com/PlexSheep/kauma/commit/e249b6c499f38cb348db8ee613ca676f12f19c3e))
* **ffield:** make mul work with a horrible hack, but I don't know how else to do it ([cffffbe](https://github.com/PlexSheep/kauma/commit/cffffbe77c62031d63836f452f62722f466e82a9))
* **ffield:** perform gfmul action ([db3d5d3](https://github.com/PlexSheep/kauma/commit/db3d5d315a79b010b3058a87f5925751aa390bd2))
* **ffield:** work on poly2block and block2poly ([dbf76c2](https://github.com/PlexSheep/kauma/commit/dbf76c23d2e2cb46899ade3c02306842e1a6069f))
* make use of threadpools and allow the user to set a thread count in an environment variable ([f80be65](https://github.com/PlexSheep/kauma/commit/f80be6516379330221576b641d346635edf70a57))
* **poly2block:** works ([fb30a41](https://github.com/PlexSheep/kauma/commit/fb30a41d4348af48c814cb539493de33009d3dd0))
* print challenge type to stderr on start and end ([c7981bc](https://github.com/PlexSheep/kauma/commit/c7981bc063dc5c5f4ba6873376616f7bc2234d56))
* select and run testcases with the specified json format ([37b7c53](https://github.com/PlexSheep/kauma/commit/37b7c53df7a9c849087a51190b0ce47ebfc1992e))


### Bug Fixes

* add common as a module ([34c5d39](https://github.com/PlexSheep/kauma/commit/34c5d39c25d1d346e2c0714f2d8ae81125dfe2d7))
* **c1:** adjust the DEFINING_RELATION_F_2_128 to what I think is correct ([3e1f07d](https://github.com/PlexSheep/kauma/commit/3e1f07d14c5e4d6ad70b7c6d913ca1cad39c1647))
* **cipher:** deencrypt the xor'd data instead of the ciphertext ([630b9fc](https://github.com/PlexSheep/kauma/commit/630b9fca228c7a9ce8ace8f40d57959ebdd5d2e2))
* **cipher:** fix xor in decryption for sea_128 ([090eda0](https://github.com/PlexSheep/kauma/commit/090eda08fbcc69e23804df36f0f7211b0d1fe79e))
* **cipher:** used the first key for tweak encryption and the second for block encryption in xex mode ([0c443a7](https://github.com/PlexSheep/kauma/commit/0c443a7ad57a94b19642adff2ed6a62754e15e73))
* **common:** bytes_to_u128 paniced when input was too large, because the length was not being checked correctly ([de82715](https://github.com/PlexSheep/kauma/commit/de827156a811d2aa553e176258242eb79290c218))
* don't report an envvar error if the envvar is just not defined ([3cb4804](https://github.com/PlexSheep/kauma/commit/3cb48041e00ed853da767295662dbca8c09011a6))
* **ffield:** block2poly sort is required to be ascending ([79db6c7](https://github.com/PlexSheep/kauma/commit/79db6c7a90d105876529c0ed990dea5f0f2dbc2b))
* **ffield:** simplified mul works ([025a5c4](https://github.com/PlexSheep/kauma/commit/025a5c4d4ecb5e7ef14b5932e8d23e97aa699212))
* **ffield:** simplified mul works ([1651df3](https://github.com/PlexSheep/kauma/commit/1651df3a77e80b3563c5ffbd9e9c39df74d5cbee))
* **ffield:** simplified mul works ([78b9a7f](https://github.com/PlexSheep/kauma/commit/78b9a7f0c18ac66d6ef62a60ad6a0361d8fa6afd))
* **msrv:** use map_err instead of inspect_err to support rustc 1.75 ([3e9fd36](https://github.com/PlexSheep/kauma/commit/3e9fd36679a05d550c707928bc870a06d004ac22))
* mul_alpha run if poly_a is alpha ([1d30e80](https://github.com/PlexSheep/kauma/commit/1d30e8023562af378eee6eb95c466885b2efe410))
* result handling for jobs was wrong (recv_timeout wraps in a result) ([6d211c2](https://github.com/PlexSheep/kauma/commit/6d211c2e766df2d87b0ad880461c833bc5709a5a))
