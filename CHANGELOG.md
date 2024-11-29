# Changelog

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