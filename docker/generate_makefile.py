# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Simple generator for local Makefile rules."""

import os
import sys

from common import yaml_utils
from common import benchmark_utils
from common import fuzzer_utils
from experiment.build import docker_images

BASE_TAG = "gcr.io/fuzzbench"
BENCHMARK_DIR = benchmark_utils.BENCHMARKS_DIR

IMAGES_DIGEST = {
   "gcr.io/fuzzbench/base-image":"sha256:561cbc2a0961a202efb5d5c9fda1cc331be453e6b2bf39d1d91785c8fdd70e99",
   "gcr.io/fuzzbench/dispatcher-image":"sha256:b0367850f99603cf0c7938505de0861ccb284f1fcae44fbdc940110e900d103f",
   "gcr.io/fuzzbench/worker":"sha256:cd2aac3becdbaaae92403135bac9744b0790cb52eaea9218574bde2d2e8f641d",
   "gcr.io/fuzzbench/builders/benchmark/bloaty_fuzz_target":"sha256:932ecba833f0003bc32c67d474bcf630ed3887585fea760bde165b22c79eb77b",
   "gcr.io/fuzzbench/builders/coverage/bloaty_fuzz_target-intermediate":"sha256:8a8b8d422fb4d9e374dc87dab1a798a4310810dd5f99580e10d6f4975a35cd3a",
   "gcr.io/fuzzbench/builders/coverage/bloaty_fuzz_target":"sha256:c1ed8b2d257a5b81aacb0c5a7ef67e523cc7415f888cc2d598a8d23e0e7f1a05",
   "gcr.io/fuzzbench/builders/honggfuzz/bloaty_fuzz_target-intermediate":"sha256:3f701912f8880ad09d05ff04cbfd46eaffc5d129ecd56fa664068b9f833f6cd7",
   "gcr.io/fuzzbench/builders/honggfuzz/bloaty_fuzz_target":"sha256:e267847a57646c8732b2327d367b3e5bf7a03662810819c061aa84ad0647e5a8",
   "gcr.io/fuzzbench/runners/honggfuzz/bloaty_fuzz_target-intermediate":"sha256:8718f1f570e0ec5e5843902c8cb052b662302ba662844a983cc31fff250127b1",
   "gcr.io/fuzzbench/runners/honggfuzz/bloaty_fuzz_target":"sha256:5d623ae9a9e0cc73f7ed19ed799f42c05e6f387f0dc79636938ffb5566176ad9",
   "gcr.io/fuzzbench/builders/aflplusplus/bloaty_fuzz_target-intermediate":"sha256:0371d1cc9b01424a4a6facc18086f9bd349f152f9ed8d7994baf4a388b24b137",
   "gcr.io/fuzzbench/builders/aflplusplus/bloaty_fuzz_target":"sha256:b055d2e9c7509cf5a0051369bc4db294b225768d718f87f3e2368def558076ef",
   "gcr.io/fuzzbench/runners/aflplusplus/bloaty_fuzz_target-intermediate":"sha256:4017f2bd600a7729de9fb5e9df7ec7db845c1af17f8ce10f0107409851fe4b8f",
   "gcr.io/fuzzbench/runners/aflplusplus/bloaty_fuzz_target":"sha256:57a821fdf563add1e22910e63870925d25f17571327d007cdb6c15ad164b5f5b",
   "gcr.io/fuzzbench/builders/afl/bloaty_fuzz_target-intermediate":"sha256:d7fa1781d91997d7613f50860cf22b532ef1650287fb360687be07d8d911e9f7",
   "gcr.io/fuzzbench/builders/afl/bloaty_fuzz_target":"sha256:5f7ed17f81c71ee352edca8088ba7dfd655e1cf7762950220c8eb432c0d9a1e4",
   "gcr.io/fuzzbench/runners/afl/bloaty_fuzz_target-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/afl/bloaty_fuzz_target":"sha256:f1f188337b16747a70b6cc9f0a4cf5dfe078fd51f4c3e73918c08d3e02c1255f",
   "gcr.io/fuzzbench/builders/entropic/bloaty_fuzz_target-intermediate":"sha256:fe76f7771856f620b8ef6c4cfdf84dd5547eebf50fe1fb11f801218cc842efe3",
   "gcr.io/fuzzbench/builders/entropic/bloaty_fuzz_target":"sha256:215e5fdffd16cd2b03a230202dba8ae8b45fa0d7ee2e926a5a206883ec26a0f0",
   "gcr.io/fuzzbench/runners/entropic/bloaty_fuzz_target-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/entropic/bloaty_fuzz_target":"sha256:dbcdeab728644eb8165e7f38cdb219156898c31d125b2a3d243061aedb4d712e",
   "gcr.io/fuzzbench/builders/libfuzzer/bloaty_fuzz_target-intermediate":"sha256:09130e4440473ff5f6eb66a90cd0cedee21bdfbab1f941490c353eb5df2fcfc3",
   "gcr.io/fuzzbench/builders/libfuzzer/bloaty_fuzz_target":"sha256:15456d2355f08efc4aa3b0382c756f09310e52b68bdacd9a9e6b89023df152f7",
   "gcr.io/fuzzbench/runners/libfuzzer/bloaty_fuzz_target-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/libfuzzer/bloaty_fuzz_target":"sha256:8bf1e3c879656afc18a01caf5c505ca3540a3c133a24a68ab82cecf23ea61d21",
   "gcr.io/fuzzbench/builders/eclipser/bloaty_fuzz_target-intermediate":"sha256:ece89627ec2a3577fe51ad806a72a5dd91a5439b8a64df477954a3b205f8efcd",
   "gcr.io/fuzzbench/builders/eclipser/bloaty_fuzz_target":"sha256:b96e213fd43014d453e81aceaf9b26ef64600c1b9d1bb5123f62dc726f682dec",
   "gcr.io/fuzzbench/runners/eclipser/bloaty_fuzz_target-intermediate":"sha256:5626de61cd5600a29326d0b1283b672af059716c90602a0f3f320a4ab35cd805",
   "gcr.io/fuzzbench/runners/eclipser/bloaty_fuzz_target":"sha256:483b9002b8ff75e44990d50287f49b223a10472fcce4012085b8547259996afe",
   "gcr.io/fuzzbench/builders/benchmark/curl_curl_fuzzer_http":"sha256:3f955a2e94293c5a71d926c2ee18a26ff152e3400ec339c4bd02a2069c76de1e",
   "gcr.io/fuzzbench/builders/coverage/curl_curl_fuzzer_http-intermediate":"sha256:f23a7d894d709c959cdc5f6b92d746d5d92355ac68746a98e6ca7658d42f26c8",
   "gcr.io/fuzzbench/builders/coverage/curl_curl_fuzzer_http":"sha256:1d7bdccc5ae15f75842baf5052e111b7d2629653f9232d68301ef56bff0f0714",
   "gcr.io/fuzzbench/builders/honggfuzz/curl_curl_fuzzer_http-intermediate":"sha256:8d7f6e17fbf21fa54f8adfe0a52bcffbbba3ed17915f35d9c399f5df82cbfb5e",
   "gcr.io/fuzzbench/builders/honggfuzz/curl_curl_fuzzer_http":"sha256:07b8ea0560eeb578c2469efd6a461575576efa443226be91b8036a4f524dbd76",
   "gcr.io/fuzzbench/runners/honggfuzz/curl_curl_fuzzer_http-intermediate":"sha256:acff4e523df74e676e96aa5356aa5d30179f7253367ae5bb4f5fd2f65b14201b",
   "gcr.io/fuzzbench/runners/honggfuzz/curl_curl_fuzzer_http":"sha256:c7595f2d25a8d7f8dc64458a7f9d8675ac7ea348289f8b71bfa07788a6fbb9d1",
   "gcr.io/fuzzbench/builders/aflplusplus/curl_curl_fuzzer_http-intermediate":"sha256:55701630379355f7f381d133a27a91f182ccfe5676500df2e5d6eb22ba7cb8a1",
   "gcr.io/fuzzbench/builders/aflplusplus/curl_curl_fuzzer_http":"sha256:5bf6a3a7329b117ab96aaad77ac08075b6c8944dffc6475cbb0c38ee2ab4a11a",
   "gcr.io/fuzzbench/runners/aflplusplus/curl_curl_fuzzer_http-intermediate":"sha256:4017f2bd600a7729de9fb5e9df7ec7db845c1af17f8ce10f0107409851fe4b8f",
   "gcr.io/fuzzbench/runners/aflplusplus/curl_curl_fuzzer_http":"sha256:f90dca1dec33c37de73f88faa9e2c7d2ad52e42847bb5b96d066b32a9a176e11",
   "gcr.io/fuzzbench/builders/afl/curl_curl_fuzzer_http-intermediate":"sha256:2a13cd5f3aa03703466bbe6238014e2b4d9895a20be83b669b5c2bf3eb6a3ec4",
   "gcr.io/fuzzbench/builders/afl/curl_curl_fuzzer_http":"sha256:e9a83c0bfabade1089b95b07bde0e704d915f8494c1621fae3913a3f4bb80046",
   "gcr.io/fuzzbench/runners/afl/curl_curl_fuzzer_http-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/afl/curl_curl_fuzzer_http":"sha256:805ec8628823c94333242e89293834894489228fc18e44a737c8a08e8ef70367",
   "gcr.io/fuzzbench/builders/entropic/curl_curl_fuzzer_http-intermediate":"sha256:1e1fd20e950ad9f14d79cfade2bc4079bf2ba64b70661aed2cd64161e9d3b1b9",
   "gcr.io/fuzzbench/builders/entropic/curl_curl_fuzzer_http":"sha256:e1b0c3243a1d41757cdcca6d5e88b370ab5bc2c9ffb209c42c2d3420684e404c",
   "gcr.io/fuzzbench/runners/entropic/curl_curl_fuzzer_http-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/entropic/curl_curl_fuzzer_http":"sha256:03eb64ab05e51abb1f55fe8b217c3cf97a986cdedaca9e708c56e7d17c0cd7fd",
   "gcr.io/fuzzbench/builders/libfuzzer/curl_curl_fuzzer_http-intermediate":"sha256:f5dc40b80bbe6b42a6d1e1899484955c3a4e95ecbe219bfeb8f0348395e36104",
   "gcr.io/fuzzbench/builders/libfuzzer/curl_curl_fuzzer_http":"sha256:96781ee33f9a6a68f198e4fa1228d6c56d4f6f161d8f6aeabf6ebb7d225718fe",
   "gcr.io/fuzzbench/runners/libfuzzer/curl_curl_fuzzer_http-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/libfuzzer/curl_curl_fuzzer_http":"sha256:39455521b460ee2997c227dd3c60da13482fc6c29a1211e26511a66348b14aed",
   "gcr.io/fuzzbench/builders/eclipser/curl_curl_fuzzer_http-intermediate":"sha256:a53894e3862a7195061b8ceb881b0b13e3b51eaa7b1b1ac88c76eb0e6f725070",
   "gcr.io/fuzzbench/builders/eclipser/curl_curl_fuzzer_http":"sha256:8642a4fb892641970c8abf1d0328f6301d652f03fe9aca8dbebe8b936f404e7e",
   "gcr.io/fuzzbench/runners/eclipser/curl_curl_fuzzer_http-intermediate":"sha256:7dc3396ef27f1852b61f7ac224144bbd850e203af9d5097d19ce8cd21ae58ba5",
   "gcr.io/fuzzbench/runners/eclipser/curl_curl_fuzzer_http":"sha256:7e33591a88247a81f9df4ff0ef52a76577ae5a5f84973761b4455c8b5c8dafba",
   "gcr.io/fuzzbench/builders/benchmark/freetype2-2017":"sha256:c67eb35320e5a7c6a35dbcf4d2ce9b55ea76358e5589acb5c76a29e1868ebf48",
   "gcr.io/fuzzbench/builders/coverage/freetype2-2017-intermediate":"sha256:eca8760a1f5fa13f0127803bb5246b980ee582685d39e0d635bb7939dd513d58",
   "gcr.io/fuzzbench/builders/coverage/freetype2-2017":"sha256:931e652427c32f2a629b9b9665f0f5b3bd35ef4ebda086f189cb2b4cad951759",
   "gcr.io/fuzzbench/builders/honggfuzz/freetype2-2017-intermediate":"sha256:27532e227ff37897b7413ee1f16e1e6d8b7615c393eb1c7f3ae1f359b8c2bb05",
   "gcr.io/fuzzbench/builders/honggfuzz/freetype2-2017":"sha256:e447c788a15d351431870818af8ddf00365b3c7442abb07f15d0719f8acfd957",
   "gcr.io/fuzzbench/runners/honggfuzz/freetype2-2017-intermediate":"sha256:f11de8555fef7ee50adc6ddc717e49092027b4595ea2a5b96481da16ac2b9f5e",
   "gcr.io/fuzzbench/runners/honggfuzz/freetype2-2017":"sha256:641bc22ffb2f8e14e15859978526d8c5f2cdd96f731fcafe62414b6d32794441",
   "gcr.io/fuzzbench/builders/aflplusplus/freetype2-2017-intermediate":"sha256:8d9027315f5773a3b5960b46cb92dde07d10d54dd7b2e704f96f02f05da55801",
   "gcr.io/fuzzbench/builders/aflplusplus/freetype2-2017":"sha256:9e27f558841d56c0ffebc03eb4e545cb3a1ab8ba719e2b73b613e05ceb65525a",
   "gcr.io/fuzzbench/runners/aflplusplus/freetype2-2017-intermediate":"sha256:4017f2bd600a7729de9fb5e9df7ec7db845c1af17f8ce10f0107409851fe4b8f",
   "gcr.io/fuzzbench/runners/aflplusplus/freetype2-2017":"sha256:fdecaf39e8362e00476dda75eb32215b3feead388166a48f78b7eab375bed73c",
   "gcr.io/fuzzbench/builders/afl/freetype2-2017-intermediate":"sha256:cf4ef8f0ac5f49a476d48023529f0415c5c793c50948ed4da1df15a023774b3b",
   "gcr.io/fuzzbench/builders/afl/freetype2-2017":"sha256:89d3a628b44c7505b44d73153f7a7eb99bf97aade2f5fa877942af95e5fec2cc",
   "gcr.io/fuzzbench/runners/afl/freetype2-2017-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/afl/freetype2-2017":"sha256:9ad9a8679d2a79d6b664c7935607512aebb026f472ab90d298113362593b0eca",
   "gcr.io/fuzzbench/builders/entropic/freetype2-2017-intermediate":"sha256:f1ff96f090aba26bfc219caf5e4d5056949dae3f83435502dfe7cbedb048d54b",
   "gcr.io/fuzzbench/builders/entropic/freetype2-2017":"sha256:9a2338384791951512796b6842f676dc305a63d8d16d09fab243ba78ae636e96",
   "gcr.io/fuzzbench/runners/entropic/freetype2-2017-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/entropic/freetype2-2017":"sha256:ec31a6eba87316520a8635c887adaf49d67a286f2d5e56ef84af442544c0b85b",
   "gcr.io/fuzzbench/builders/libfuzzer/freetype2-2017-intermediate":"sha256:837286317b76c37ddb3fb936ed432152bafef2abe5fc2d9da131970f6dbb5063",
   "gcr.io/fuzzbench/builders/libfuzzer/freetype2-2017":"sha256:4f155215de8d2b11c8eab069dc211e93eb411cff0912f9ad232a07e8b13a8252",
   "gcr.io/fuzzbench/runners/libfuzzer/freetype2-2017-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/libfuzzer/freetype2-2017":"sha256:10eb7c0b6e910416ad2a738f19f2970c2c3d911a75bd06a7ee32170c780875d8",
   "gcr.io/fuzzbench/builders/eclipser/freetype2-2017-intermediate":"sha256:ae227cf0c1ea6fff4dfc25d35090eede9af59b47fc51a5b0cbc9e5425ed9ef68",
   "gcr.io/fuzzbench/builders/eclipser/freetype2-2017":"sha256:5c1a07d10c056a40a8547a9f67e83e5a23106010764ad7fbb0716ada550c5ba8",
   "gcr.io/fuzzbench/runners/eclipser/freetype2-2017-intermediate":"sha256:b3ded6016a0bf450552be67d3ad7953bfa6aa6fe1a798af32e5866bff1829f39",
   "gcr.io/fuzzbench/runners/eclipser/freetype2-2017":"sha256:d4f9f791e726e63eb6b6cd69e2413282cfa984c9af26a8f4e9684f44aa0ad2f8",
   "gcr.io/fuzzbench/builders/benchmark/harfbuzz-1.3.2":"sha256:b3be173823e6e2a1105dd0b2c50e3317763bc512a5303f199ecd166f2cccf16c",
   "gcr.io/fuzzbench/builders/coverage/harfbuzz-1.3.2-intermediate":"sha256:72c0c9ec28ca46508760bb29cedc8c0e2391d32c5fd66f80944ec5a19a4800b8",
   "gcr.io/fuzzbench/builders/coverage/harfbuzz-1.3.2":"sha256:e750780c43d22fe94967a62ce719cba6e8a166f224a47df67a0f7c2b371d6103",
   "gcr.io/fuzzbench/builders/honggfuzz/harfbuzz-1.3.2-intermediate":"sha256:e1d0b616d3a54521ee64156be30defcc1d6de03d8eb049b85fe0acc7a41af4a4",
   "gcr.io/fuzzbench/builders/honggfuzz/harfbuzz-1.3.2":"sha256:6d602ca59bb2ab9f8b0ab51047e1c1b0651689477a757e464410932c8fd96c53",
   "gcr.io/fuzzbench/runners/honggfuzz/harfbuzz-1.3.2-intermediate":"sha256:bdfca561db8ad338536ee1d8b892024082be047b8184d1dc8f5cd6ee9ed083df",
   "gcr.io/fuzzbench/runners/honggfuzz/harfbuzz-1.3.2":"sha256:f0a6bbe5bae329eed9144e1aaf1aacbdd9b54eb6bb7b38b873a4717953eaea34",
   "gcr.io/fuzzbench/builders/aflplusplus/harfbuzz-1.3.2-intermediate":"sha256:2c464d70a973fe749b0ea5cd631f91fc68f674110b2a542f4383c43fa8676e3b",
   "gcr.io/fuzzbench/builders/aflplusplus/harfbuzz-1.3.2":"sha256:ec716a9eab77d8b1364f3e92fde6fa8197754aeb478344604a1298f87e517e94",
   "gcr.io/fuzzbench/runners/aflplusplus/harfbuzz-1.3.2-intermediate":"sha256:cfbc1d44c388d6af98f5ec467aab8497b45279002e71c700f51ef0b4de05cd28",
   "gcr.io/fuzzbench/runners/aflplusplus/harfbuzz-1.3.2":"sha256:fba37df2e3cd46e093089e1cc89c99e20730f3e69fa22d6c695eeb9fa200e2fe",
   "gcr.io/fuzzbench/builders/afl/harfbuzz-1.3.2-intermediate":"sha256:efbbd7e695f4bfa832ee002d99647848884a17df8f9159c38c9ab2f38448b553",
   "gcr.io/fuzzbench/builders/afl/harfbuzz-1.3.2":"sha256:1a35e7b9b68fa5b9857af07156c64348c363fb9509557e1884cc020a65d2ca56",
   "gcr.io/fuzzbench/runners/afl/harfbuzz-1.3.2-intermediate":"sha256:af6ef89dce3084ff3eccd97f93aa227f51d6104c77c5a500358f83d02d5e2122",
   "gcr.io/fuzzbench/runners/afl/harfbuzz-1.3.2":"sha256:d53c895e18b12f0b369a4ba9efb9db0a26bb0c0bc320fe427fd22c5e02733df2",
   "gcr.io/fuzzbench/builders/entropic/harfbuzz-1.3.2-intermediate":"sha256:047219288591ccc030b6698e747d719241d9dab55f72f987696acba9c7ed2b10",
   "gcr.io/fuzzbench/builders/entropic/harfbuzz-1.3.2":"sha256:63ccf74c5a96da74a9e4928783526bd93cda4d0be742d9f8f930dc5318a6e75b",
   "gcr.io/fuzzbench/runners/entropic/harfbuzz-1.3.2-intermediate":"sha256:af6ef89dce3084ff3eccd97f93aa227f51d6104c77c5a500358f83d02d5e2122",
   "gcr.io/fuzzbench/runners/entropic/harfbuzz-1.3.2":"sha256:79b64434b5a3b60517216aac7dd8c62a368ac7d1a03ab7114e6630eb30f82b7f",
   "gcr.io/fuzzbench/builders/libfuzzer/harfbuzz-1.3.2-intermediate":"sha256:2c6e858db8aac0e9d65c551131a9bd66e5387706e01c588bab6b84446c9cc0f3",
   "gcr.io/fuzzbench/builders/libfuzzer/harfbuzz-1.3.2":"sha256:951bf53a3124a0c31532a5f6b477925528b6d39df7c0ddef307ca0191f06a379",
   "gcr.io/fuzzbench/runners/libfuzzer/harfbuzz-1.3.2-intermediate":"sha256:af6ef89dce3084ff3eccd97f93aa227f51d6104c77c5a500358f83d02d5e2122",
   "gcr.io/fuzzbench/runners/libfuzzer/harfbuzz-1.3.2":"sha256:da07ed69b81476ec1afca39536da184bcf1bf0676312b7803647666bcc056a29",
   "gcr.io/fuzzbench/builders/eclipser/harfbuzz-1.3.2-intermediate":"sha256:fb4f6e66d5852225cc2e8e22d781e6614f612faea8e0251dc369b733e8fa63a2",
   "gcr.io/fuzzbench/builders/eclipser/harfbuzz-1.3.2":"sha256:8552bc2fd438b188cd7b77ed915b0c9e9da7eba8146ae20abe3a9502e58694d6",
   "gcr.io/fuzzbench/runners/eclipser/harfbuzz-1.3.2-intermediate":"sha256:a045d34dd3e2a4d0223666e4f25a0aba697001e84c046be1c9a2a058b3ffa19e",
   "gcr.io/fuzzbench/runners/eclipser/harfbuzz-1.3.2":"sha256:616ed435590aa4f07c8b931da407b81a350c34c95d26e02e4742707798dc5e48",
   "gcr.io/fuzzbench/builders/benchmark/jsoncpp_jsoncpp_fuzzer":"sha256:316ad3790e5706ebdf0c3b0fa16b2230ae7bdf14a2d6e35438c70b55573499de",
   "gcr.io/fuzzbench/builders/coverage/jsoncpp_jsoncpp_fuzzer-intermediate":"sha256:ce52aa123510cca6cec9953a649de073d929dc905602901c5dd60c23e61b9dcb",
   "gcr.io/fuzzbench/builders/coverage/jsoncpp_jsoncpp_fuzzer":"sha256:9c19787600f783d282f659a17b8a95fe9871aa1dc19c856038d43b97bbb05080",
   "gcr.io/fuzzbench/builders/honggfuzz/jsoncpp_jsoncpp_fuzzer-intermediate":"sha256:6c3e796786d4863f65fb37eede65a39f2a994ad40a67d141a53cb68bf9fa5824",
   "gcr.io/fuzzbench/builders/honggfuzz/jsoncpp_jsoncpp_fuzzer":"sha256:20539da6d163e3d5ac1b14865ebc7adc2a77f3fa50feac3b1ad63aca7a343012",
   "gcr.io/fuzzbench/runners/honggfuzz/jsoncpp_jsoncpp_fuzzer-intermediate":"sha256:8961f4262daa20898a73cdf1eb71ac18d1fab648a20b724ee9ea601de6a145c0",
   "gcr.io/fuzzbench/runners/honggfuzz/jsoncpp_jsoncpp_fuzzer":"sha256:9b623fc8afc1a9a00961294541e8abea3c804dbd85d6210d6f7a5e4f870cd236",
   "gcr.io/fuzzbench/builders/aflplusplus/jsoncpp_jsoncpp_fuzzer-intermediate":"sha256:ed4813957722917c38405b6ed3f20fe19ebaadf28142bb123edd3585747a5926",
   "gcr.io/fuzzbench/builders/aflplusplus/jsoncpp_jsoncpp_fuzzer":"sha256:faa01da7f2cb58a8849c20b55f40f93055a11f95d793ba1eab701c834891ae4e",
   "gcr.io/fuzzbench/runners/aflplusplus/jsoncpp_jsoncpp_fuzzer-intermediate":"sha256:4017f2bd600a7729de9fb5e9df7ec7db845c1af17f8ce10f0107409851fe4b8f",
   "gcr.io/fuzzbench/runners/aflplusplus/jsoncpp_jsoncpp_fuzzer":"sha256:63b7698f94312fbffd1edcd2981e36db8096417f2be33f9f7ebd95af9a8f0519",
   "gcr.io/fuzzbench/builders/afl/jsoncpp_jsoncpp_fuzzer-intermediate":"sha256:a04cdf20e012a0a6f41e8c023b04411520e1a5fda5b161e64e7d72dc50532505",
   "gcr.io/fuzzbench/builders/afl/jsoncpp_jsoncpp_fuzzer":"sha256:f85f957c29b67520030b4cc3bf41f6661442aeead56f833c90448efd626c72dd",
   "gcr.io/fuzzbench/runners/afl/jsoncpp_jsoncpp_fuzzer-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/afl/jsoncpp_jsoncpp_fuzzer":"sha256:1345eb8edf29468e5fb62cfd1f3b25ebb00b076c5ee1c90785419d8312f23887",
   "gcr.io/fuzzbench/builders/entropic/jsoncpp_jsoncpp_fuzzer-intermediate":"sha256:240c24477a3d1a512f1b00fd010483f96a16c8b79914610d4c742674ef47f531",
   "gcr.io/fuzzbench/builders/entropic/jsoncpp_jsoncpp_fuzzer":"sha256:74a10a9003a9a5b053d05234c72ddad08f9ca444c8008d124aa1a6e085a8a32e",
   "gcr.io/fuzzbench/runners/entropic/jsoncpp_jsoncpp_fuzzer-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/entropic/jsoncpp_jsoncpp_fuzzer":"sha256:65a503461d363c77a520c0a9a75444b34ec28bff198969785774f281a1ba4016",
   "gcr.io/fuzzbench/builders/libfuzzer/jsoncpp_jsoncpp_fuzzer-intermediate":"sha256:966f21e4b86671447272fce0991f0e18ce7bc6497ec7f78cbd7e33ec052995f5",
   "gcr.io/fuzzbench/builders/libfuzzer/jsoncpp_jsoncpp_fuzzer":"sha256:6366c80b8a7d80f9a90cacbb9522d6d70d25fb24272c997cb456bd71a8d48766",
   "gcr.io/fuzzbench/runners/libfuzzer/jsoncpp_jsoncpp_fuzzer-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/libfuzzer/jsoncpp_jsoncpp_fuzzer":"sha256:b61f64d0c1f4459838700ebb3b19b063df5af62cd1a09018865f2e5c7f4264d9",
   "gcr.io/fuzzbench/builders/eclipser/jsoncpp_jsoncpp_fuzzer-intermediate":"sha256:ce6d2f7a8a3c8b1e1af4b800622aac49c0ee3dbe85474d28043e059335ea8cc2",
   "gcr.io/fuzzbench/builders/eclipser/jsoncpp_jsoncpp_fuzzer":"sha256:d8fe14a7b24b6d493e388545a590259ec6e9507cc0486a486be6035be52b68f2",
   "gcr.io/fuzzbench/runners/eclipser/jsoncpp_jsoncpp_fuzzer-intermediate":"sha256:d8241551e44954b20d07dda5822392475fc8e3de35573a314c00bd79e2512886",
   "gcr.io/fuzzbench/runners/eclipser/jsoncpp_jsoncpp_fuzzer":"sha256:23d382a949ae603033015e68381b716a107f7d91e444ace206fd7cbf217fd5cf",
   "gcr.io/fuzzbench/builders/benchmark/lcms-2017-03-21":"sha256:72a961042d273cd5a5b84d1d566c9851fbbd5768adf1d599eb9f6883ebad0636",
   "gcr.io/fuzzbench/builders/coverage/lcms-2017-03-21-intermediate":"sha256:6f4333c70b0e4f1afb209ac62f1250102f36478c97918147078aadd01112a800",
   "gcr.io/fuzzbench/builders/coverage/lcms-2017-03-21":"sha256:b1605dce161e7fa675bd8cfddfe91ad6e101f062752f5e0a525bad83390f3061",
   "gcr.io/fuzzbench/builders/honggfuzz/lcms-2017-03-21-intermediate":"sha256:5cffc86b225d38860c75dc6d4365963e2061006290bae2444029c2b7c6dc6e4c",
   "gcr.io/fuzzbench/builders/honggfuzz/lcms-2017-03-21":"sha256:b1d3d48228e778c381196f762890998c736e4609500d20bd46f002b817945484",
   "gcr.io/fuzzbench/runners/honggfuzz/lcms-2017-03-21-intermediate":"sha256:fbc6377a4f1d4cb30d240d3e6a1dac771d5278601666c51ccf87f4caa016c0b7",
   "gcr.io/fuzzbench/runners/honggfuzz/lcms-2017-03-21":"sha256:147ce1150529c229e8e6f33793a2447fffb8b115a60f86a8900bde832958828b",
   "gcr.io/fuzzbench/builders/aflplusplus/lcms-2017-03-21-intermediate":"sha256:f66698ca6647caa52f04a332d457a1f5f7a8e57f6d97593edf9831bf723a1b5b",
   "gcr.io/fuzzbench/builders/aflplusplus/lcms-2017-03-21":"sha256:6822c90a93be57fbcfc30ca8b77c7e389bbaf669372eb5c59394ed1ee4e6c25b",
   "gcr.io/fuzzbench/runners/aflplusplus/lcms-2017-03-21-intermediate":"sha256:cfbc1d44c388d6af98f5ec467aab8497b45279002e71c700f51ef0b4de05cd28",
   "gcr.io/fuzzbench/runners/aflplusplus/lcms-2017-03-21":"sha256:048cf5465f12e837550ded195283e4c30e6d1118f340ab178eadff89eba0c293",
   "gcr.io/fuzzbench/builders/afl/lcms-2017-03-21-intermediate":"sha256:2d90b8ffea701516e5b44057ad03872fad5887a5628a8b49db598d516cbbe8c0",
   "gcr.io/fuzzbench/builders/afl/lcms-2017-03-21":"sha256:9270c74ae76b02891810d4c6eb87488d53717b8c72ff986caf34405911e86b4c",
   "gcr.io/fuzzbench/runners/afl/lcms-2017-03-21-intermediate":"sha256:af6ef89dce3084ff3eccd97f93aa227f51d6104c77c5a500358f83d02d5e2122",
   "gcr.io/fuzzbench/runners/afl/lcms-2017-03-21":"sha256:fa3ae593f698e941bfc1a15e10ecfb8c7626d7b6d1ea370079cb2f6ef1ae5943",
   "gcr.io/fuzzbench/builders/entropic/lcms-2017-03-21-intermediate":"sha256:035ae326b7d5a43abd0ec36275c7a504160e2935997852c8402b280f2ee55d4c",
   "gcr.io/fuzzbench/builders/entropic/lcms-2017-03-21":"sha256:7250994c86c6003fa740a9d697c9155328a536184be00b3e7b5edfed4c653f29",
   "gcr.io/fuzzbench/runners/entropic/lcms-2017-03-21-intermediate":"sha256:af6ef89dce3084ff3eccd97f93aa227f51d6104c77c5a500358f83d02d5e2122",
   "gcr.io/fuzzbench/runners/entropic/lcms-2017-03-21":"sha256:39163ae2ed61b4b53c23b788a90bf5f2393bc9487caf606e567e75fa85e55b82",
   "gcr.io/fuzzbench/builders/libfuzzer/lcms-2017-03-21-intermediate":"sha256:863cbd0a20f9fc7eed96da23d58c5913c2ef7909c6844a8bd5ac588227539f90",
   "gcr.io/fuzzbench/builders/libfuzzer/lcms-2017-03-21":"sha256:0360bd9e67351e0856b021075bcd182a5409c132c5ec6f5d93532aac28ab040b",
   "gcr.io/fuzzbench/runners/libfuzzer/lcms-2017-03-21-intermediate":"sha256:af6ef89dce3084ff3eccd97f93aa227f51d6104c77c5a500358f83d02d5e2122",
   "gcr.io/fuzzbench/runners/libfuzzer/lcms-2017-03-21":"sha256:0e9d71ef8eb0ada18dfc65f41dab841e222f027fc80c8218e0fbbf7e084040e3",
   "gcr.io/fuzzbench/builders/eclipser/lcms-2017-03-21-intermediate":"sha256:d2258a778130dc72934336758853e801488221066bd984e987633d8523499a03",
   "gcr.io/fuzzbench/builders/eclipser/lcms-2017-03-21":"sha256:1b65da2115d9df33ceddca54d8a86c40bcb4296e6a3ae4bfb8982af8cdf0219d",
   "gcr.io/fuzzbench/runners/eclipser/lcms-2017-03-21-intermediate":"sha256:90cd08bc7140da3baa5fa07a71fb9746a149728d6541c40f3b40a8cba285b593",
   "gcr.io/fuzzbench/runners/eclipser/lcms-2017-03-21":"sha256:457959f524c46731845b096750db64614b1670c7eccd9f2531a2d370ce9b658e",
   "gcr.io/fuzzbench/builders/benchmark/libjpeg-turbo-07-2017":"sha256:6de35f13981ea8d3bcf7d0c16eb434822f1f6180eefe0ea15e052e135413f58a",
   "gcr.io/fuzzbench/builders/coverage/libjpeg-turbo-07-2017-intermediate":"sha256:2bc3c523c7a04d92d56b3d335638f9489fcc8d9cf46f3bb82d0b035053f8d76c",
   "gcr.io/fuzzbench/builders/coverage/libjpeg-turbo-07-2017":"sha256:02d80d36b9042956df719201477c94e3c5d955ae457c083254d3567cc2ab0523",
   "gcr.io/fuzzbench/builders/honggfuzz/libjpeg-turbo-07-2017-intermediate":"sha256:25b3b2e25896a966ecea25f0d4a1febe3c2be7556254d82a84ef7604180d5883",
   "gcr.io/fuzzbench/builders/honggfuzz/libjpeg-turbo-07-2017":"sha256:b1eb1f7bf5482395f83a791d7e5d00cf973ad83a4d0ee91afa62e87ea74533c5",
   "gcr.io/fuzzbench/runners/honggfuzz/libjpeg-turbo-07-2017-intermediate":"sha256:e5bdcfd49153927354eb6f4ec0f3c8f35b1aae89bbc969378048904bbdac591d",
   "gcr.io/fuzzbench/runners/honggfuzz/libjpeg-turbo-07-2017":"sha256:b23b1ca86cbf5fbd7ce0ef564f6b1b490c39f8a62ec98e3e579a6f2b52dd609c",
   "gcr.io/fuzzbench/builders/aflplusplus/libjpeg-turbo-07-2017-intermediate":"sha256:ca4ed2ec7fca47a2e8e031439d2878478e5c9abc4d02adc22eb079ebb51eb5c0",
   "gcr.io/fuzzbench/builders/aflplusplus/libjpeg-turbo-07-2017":"sha256:3292398365cbf2285cceb4a4da9b6f3c7d06a736eb9ac68df5d1acbe734b04e9",
   "gcr.io/fuzzbench/runners/aflplusplus/libjpeg-turbo-07-2017-intermediate":"sha256:cfbc1d44c388d6af98f5ec467aab8497b45279002e71c700f51ef0b4de05cd28",
   "gcr.io/fuzzbench/runners/aflplusplus/libjpeg-turbo-07-2017":"sha256:d9260316d792b1d501101ac6dc480e1a37d9dd254f889717253146ff88a07105",
   "gcr.io/fuzzbench/builders/afl/libjpeg-turbo-07-2017-intermediate":"sha256:ed4e29718b00aaaa3148c26b2fd720f5e0e5eaa0af13fe81e509045ec9546b57",
   "gcr.io/fuzzbench/builders/afl/libjpeg-turbo-07-2017":"sha256:eefc144b048ef56b0e4be1896e1ee477f1cc12837465922f776e38fcaf90a280",
   "gcr.io/fuzzbench/runners/afl/libjpeg-turbo-07-2017-intermediate":"sha256:af6ef89dce3084ff3eccd97f93aa227f51d6104c77c5a500358f83d02d5e2122",
   "gcr.io/fuzzbench/runners/afl/libjpeg-turbo-07-2017":"sha256:caa9f693dc793430a63789d111043b19794b570df3bb4cc3ca0109bac0bc18fb",
   "gcr.io/fuzzbench/builders/entropic/libjpeg-turbo-07-2017-intermediate":"sha256:d333186ceca0e0dff395bd0934e8b077a06d7f9706e8b73f3282adf1ae302d4f",
   "gcr.io/fuzzbench/builders/entropic/libjpeg-turbo-07-2017":"sha256:d19cf14a05df050913cff0ce0d1dee939ba57745d3b76c05d07df0febffe8fd8",
   "gcr.io/fuzzbench/runners/entropic/libjpeg-turbo-07-2017-intermediate":"sha256:af6ef89dce3084ff3eccd97f93aa227f51d6104c77c5a500358f83d02d5e2122",
   "gcr.io/fuzzbench/runners/entropic/libjpeg-turbo-07-2017":"sha256:cc918c557c93cb6218d9f9aaffdca2bf2ee75edf943d243755dd90ea9b48c6df",
   "gcr.io/fuzzbench/builders/libfuzzer/libjpeg-turbo-07-2017-intermediate":"sha256:897fbb69194e3c8617d14df85ae8db75bfc39a069369d5643f768e4bb44dffb9",
   "gcr.io/fuzzbench/builders/libfuzzer/libjpeg-turbo-07-2017":"sha256:194080a1c77d03397dee9117e4aedc265eb1619c29d3a3ff7347442f3babcfe8",
   "gcr.io/fuzzbench/runners/libfuzzer/libjpeg-turbo-07-2017-intermediate":"sha256:af6ef89dce3084ff3eccd97f93aa227f51d6104c77c5a500358f83d02d5e2122",
   "gcr.io/fuzzbench/runners/libfuzzer/libjpeg-turbo-07-2017":"sha256:f0c0962c0b460c9531287f5cdefffebed8c5f2b2399d4b436bee2d45100a4747",
   "gcr.io/fuzzbench/builders/eclipser/libjpeg-turbo-07-2017-intermediate":"sha256:b0ba85cdf9c717014fa465d2cc6f5a44359ab622505298b2d63682b61ab3c31c",
   "gcr.io/fuzzbench/builders/eclipser/libjpeg-turbo-07-2017":"sha256:8aa99152f2388dfe6afaabc3019c65bb6358a923963e1238ccb8402eaba84593",
   "gcr.io/fuzzbench/runners/eclipser/libjpeg-turbo-07-2017-intermediate":"sha256:9207bbf83e9bd03a231062911dc198095b29435a76afd117bd0738470683bdfa",
   "gcr.io/fuzzbench/runners/eclipser/libjpeg-turbo-07-2017":"sha256:60d15eda6a15697a1ca927803061c9a6754d1a97d81231bc4a1111f8cadc14ab",
   "gcr.io/fuzzbench/builders/benchmark/libpcap_fuzz_both":"sha256:b4f1b92b5e1a104ee6d0d2db289b1d35a8226aee0967ef7defedd74a6b997809",
   "gcr.io/fuzzbench/builders/coverage/libpcap_fuzz_both-intermediate":"sha256:ff4460a79c5c2121a41551ecf1e8724d427245b87ce71916efef97913facfdab",
   "gcr.io/fuzzbench/builders/coverage/libpcap_fuzz_both":"sha256:e5482480ea7e1f6874610b9dcddb82c77140def8f0edd85ea7f690d8c5f5d1a0",
   "gcr.io/fuzzbench/builders/honggfuzz/libpcap_fuzz_both-intermediate":"sha256:70f004dff0a7a856263954eec63a06fc3779c40731deeccac8b048d8e5e41414",
   "gcr.io/fuzzbench/builders/honggfuzz/libpcap_fuzz_both":"sha256:01c6b80710aa74e68783de62ec2d5b35842535c399ea8bfc1ad308e590717dd8",
   "gcr.io/fuzzbench/runners/honggfuzz/libpcap_fuzz_both-intermediate":"sha256:9448fd409343ea192d8c45825672be6462984bf850b679f0c2763927cf0003d9",
   "gcr.io/fuzzbench/runners/honggfuzz/libpcap_fuzz_both":"sha256:b35d3275f5df13477c55da610109786831d3e098f2bb3fe311b06e90cc427602",
   "gcr.io/fuzzbench/builders/aflplusplus/libpcap_fuzz_both-intermediate":"sha256:b4e5577ab7985f113b71336b6980463831fabb269cd81786997938d44ef03368",
   "gcr.io/fuzzbench/builders/aflplusplus/libpcap_fuzz_both":"sha256:4b1d67e2729bc4c4b325b697293ad34f661563b452f946cd7e42f83aec9117b4",
   "gcr.io/fuzzbench/runners/aflplusplus/libpcap_fuzz_both-intermediate":"sha256:4017f2bd600a7729de9fb5e9df7ec7db845c1af17f8ce10f0107409851fe4b8f",
   "gcr.io/fuzzbench/runners/aflplusplus/libpcap_fuzz_both":"sha256:9557f9d35149a1ba0eccc687e139e89687322f2a5c3a973bf85d944a796d91e6",
   "gcr.io/fuzzbench/builders/afl/libpcap_fuzz_both-intermediate":"sha256:652b389cc4db0cb5827f741320598763b2acb6a46ef24ad54dda9fb7318a6d10",
   "gcr.io/fuzzbench/builders/afl/libpcap_fuzz_both":"sha256:8b949581288f524cc718a33e920461d6916c13d92d80226f8a262d232f8b18b2",
   "gcr.io/fuzzbench/runners/afl/libpcap_fuzz_both-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/afl/libpcap_fuzz_both":"sha256:569deb41019801909e8648f2808e0e0d65d50a37b6ff1d2a3ee1b409085d5bba",
   "gcr.io/fuzzbench/builders/entropic/libpcap_fuzz_both-intermediate":"sha256:27f828c13886006b7027464878de356e59b4c15076fff64154eab7a69624c755",
   "gcr.io/fuzzbench/builders/entropic/libpcap_fuzz_both":"sha256:5e20f4164e19bcb876edeaed3a805bf976710b4598877cc6af4fea235c0e9825",
   "gcr.io/fuzzbench/runners/entropic/libpcap_fuzz_both-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/entropic/libpcap_fuzz_both":"sha256:a3c14827bc9ff73cdd0023d333d19c3c5b2d73dcf51d6d50a45912760f04f764",
   "gcr.io/fuzzbench/builders/libfuzzer/libpcap_fuzz_both-intermediate":"sha256:0bebd8ceb9aeddd8595e061e64e524eb556257e090e044fd6da599d8a9f46bfa",
   "gcr.io/fuzzbench/builders/libfuzzer/libpcap_fuzz_both":"sha256:a67b551958b21b1ef1cc2a1129f5859fd82a59973672059cb6a8d3621810d548",
   "gcr.io/fuzzbench/runners/libfuzzer/libpcap_fuzz_both-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/libfuzzer/libpcap_fuzz_both":"sha256:c47caf2a997c7a672c3f0157e9b8fc503375d5d6c5eee65ebfb9bdb9603ec0b5",
   "gcr.io/fuzzbench/builders/eclipser/libpcap_fuzz_both-intermediate":"sha256:38ffede971a2d64aa7c7be6b235758856b6ae0bc03c26538d8148cf1e1a8763e",
   "gcr.io/fuzzbench/builders/eclipser/libpcap_fuzz_both":"sha256:6d1b4e095cd634e0684bf4bba67484b53f4a11e157ae22ffe9b8ea0d16639ba1",
   "gcr.io/fuzzbench/runners/eclipser/libpcap_fuzz_both-intermediate":"sha256:1bd7bf464c5643fbb5ef104f7b81d81e0fb39981b4a8834f382e1c330302d9b4",
   "gcr.io/fuzzbench/runners/eclipser/libpcap_fuzz_both":"sha256:fe05ec94c3105a4e0ff9b31a87f547eb405b0022e472a111b6ce8eef4b3de1cb",
   "gcr.io/fuzzbench/builders/benchmark/libpng-1.2.56":"sha256:3014b7e74dd9bf15a042e1c6b9c88619a57b30ea1d18639729a5090f2c82f5b0",
   "gcr.io/fuzzbench/builders/coverage/libpng-1.2.56-intermediate":"sha256:7659764a1e7ffacc06d211be9dc5ffb9f76c38231a152e8f665a54b7d2a010ac",
   "gcr.io/fuzzbench/builders/coverage/libpng-1.2.56":"sha256:d02778515016c7f5ddf6f82f0c270e2b45a9eff86f9b26eb403d82dccc1bf011",
   "gcr.io/fuzzbench/builders/honggfuzz/libpng-1.2.56-intermediate":"sha256:9844645899a73278d3e8fd2058e080b5baface67a201bad512e20a8a321058d0",
   "gcr.io/fuzzbench/builders/honggfuzz/libpng-1.2.56":"sha256:be6dcc6b818543b819f4edc0ec42986d6c651b344a0a911802f998fa13ad7903",
   "gcr.io/fuzzbench/runners/honggfuzz/libpng-1.2.56-intermediate":"sha256:804b5dacb9abd1847df0070d9c76313c6a6b3704f63566de87b326a3e3ead2bc",
   "gcr.io/fuzzbench/runners/honggfuzz/libpng-1.2.56":"sha256:c110d834b4232f8d8e4ce1a60d1feb248b88508951216118ee97bddcefed5cf7",
   "gcr.io/fuzzbench/builders/aflplusplus/libpng-1.2.56-intermediate":"sha256:6013dd7b55585622289f4edc1ba90b9210effe918ffab7140de73688ea75fe38",
   "gcr.io/fuzzbench/builders/aflplusplus/libpng-1.2.56":"sha256:3dc62189851ef6f9044752dfb9a5fd7e01d6d3e259dc58fc1b2a63b0768ea0ba",
   "gcr.io/fuzzbench/runners/aflplusplus/libpng-1.2.56-intermediate":"sha256:cfbc1d44c388d6af98f5ec467aab8497b45279002e71c700f51ef0b4de05cd28",
   "gcr.io/fuzzbench/runners/aflplusplus/libpng-1.2.56":"sha256:05539333243975d6c49f8358ed9687a20f83925d302a563ec972446bcd2010c1",
   "gcr.io/fuzzbench/builders/afl/libpng-1.2.56-intermediate":"sha256:df218a2ffb4676ab7403119f6f2222da2553272f8935a715d791d941631d5232",
   "gcr.io/fuzzbench/builders/afl/libpng-1.2.56":"sha256:a9d7ba434ad9fb390e2bf5f0421c236a97358a0f3ff5a450f87a9f1c47a9998f",
   "gcr.io/fuzzbench/runners/afl/libpng-1.2.56-intermediate":"sha256:af6ef89dce3084ff3eccd97f93aa227f51d6104c77c5a500358f83d02d5e2122",
   "gcr.io/fuzzbench/runners/afl/libpng-1.2.56":"sha256:c974897fe9b39b785046e8e3e267ac9032ea9dcf5bcfbe0840e6de73c0cc2873",
   "gcr.io/fuzzbench/builders/entropic/libpng-1.2.56-intermediate":"sha256:61a44203ff559b6baa53524acb016cda35d9c2523e6390abe76ce6cab16438ec",
   "gcr.io/fuzzbench/builders/entropic/libpng-1.2.56":"sha256:fe3d639576aee37fbe55cd446bc8b851b625e0c09f4e043643a9defe3a197f34",
   "gcr.io/fuzzbench/runners/entropic/libpng-1.2.56-intermediate":"sha256:af6ef89dce3084ff3eccd97f93aa227f51d6104c77c5a500358f83d02d5e2122",
   "gcr.io/fuzzbench/runners/entropic/libpng-1.2.56":"sha256:219294a015d10d469dee0bb399a1a0a4bad1c5f4e8caeb86b096221415d9564f",
   "gcr.io/fuzzbench/builders/libfuzzer/libpng-1.2.56-intermediate":"sha256:f850261133e2352b8eefc5dc312520d0b6b92d5562d22f021ca0ca9badf9d909",
   "gcr.io/fuzzbench/builders/libfuzzer/libpng-1.2.56":"sha256:4495afe2111a299266d99f2934ec84854e4e65904dfd6bc523f30df09581e753",
   "gcr.io/fuzzbench/runners/libfuzzer/libpng-1.2.56-intermediate":"sha256:af6ef89dce3084ff3eccd97f93aa227f51d6104c77c5a500358f83d02d5e2122",
   "gcr.io/fuzzbench/runners/libfuzzer/libpng-1.2.56":"sha256:2752d56b0fbbd4887b1141ffe165baa6fca019c479dfeb71850089c2c43f057f",
   "gcr.io/fuzzbench/builders/eclipser/libpng-1.2.56-intermediate":"sha256:68ce657629fc1d068fd803b95524d89c6a8c60143d2f3ea5ba78c262d40ebcaf",
   "gcr.io/fuzzbench/builders/eclipser/libpng-1.2.56":"sha256:87eca24efbe4cd692517b5029f2ec5d493066c09c3d04a33a1ba98fcd100fc9a",
   "gcr.io/fuzzbench/runners/eclipser/libpng-1.2.56-intermediate":"sha256:f340a86b964b89101b712dd583b226ca4d14a62fbe0e8a420e806d2519045b69",
   "gcr.io/fuzzbench/runners/eclipser/libpng-1.2.56":"sha256:6cc369ee8ad19cf3d4812016e126d124f27d773839f785cb6211c6160096c515",
   "gcr.io/fuzzbench/builders/benchmark/libxml2-v2.9.2":"sha256:71d35324bb27a2e16677c6415851892228e523b3b53b5c6ab1ce6d6f7b91417e",
   "gcr.io/fuzzbench/builders/coverage/libxml2-v2.9.2-intermediate":"sha256:579197c1a0b2e98c1e0003785b73c80a1465dbf097060c2e566e82b38da48a52",
   "gcr.io/fuzzbench/builders/coverage/libxml2-v2.9.2":"sha256:a4cae41db95486170d9207d07de5a14d7a5875de550202c09e74f32e24f85bf2",
   "gcr.io/fuzzbench/builders/honggfuzz/libxml2-v2.9.2-intermediate":"sha256:1d3a263418eb67acc6c174a02cc77b2093a02a0867ceed611d82381c46dc7ee1",
   "gcr.io/fuzzbench/builders/honggfuzz/libxml2-v2.9.2":"sha256:4d2637ce0839924c87532629ca581b8e14d719dae6da48144944e43cdf32c18a",
   "gcr.io/fuzzbench/runners/honggfuzz/libxml2-v2.9.2-intermediate":"sha256:bc176e8e0549e5b7394f12e9ca6e1573ea556574d42a31729eac3be970330cb0",
   "gcr.io/fuzzbench/runners/honggfuzz/libxml2-v2.9.2":"sha256:9f61a4157ebe3372e8cc72fba11eff5aa01e69e6aec7f6abe379708145fe63ce",
   "gcr.io/fuzzbench/builders/aflplusplus/libxml2-v2.9.2-intermediate":"sha256:51a78480aa00695a1c05177129549057eddab49d21239b2fd743b9696d3988b0",
   "gcr.io/fuzzbench/builders/aflplusplus/libxml2-v2.9.2":"sha256:c0fb29d615214bb1dd9c3411d160ce5a0897859de3730c703c03201bb77bc164",
   "gcr.io/fuzzbench/runners/aflplusplus/libxml2-v2.9.2-intermediate":"sha256:cfbc1d44c388d6af98f5ec467aab8497b45279002e71c700f51ef0b4de05cd28",
   "gcr.io/fuzzbench/runners/aflplusplus/libxml2-v2.9.2":"sha256:c8504f68e26f5237fa15564e9a1580a31abee0c52ef5ab3401685467bf272f33",
   "gcr.io/fuzzbench/builders/afl/libxml2-v2.9.2-intermediate":"sha256:55f0d257fc2507f8df5e67c52581d3256a0b3a91da14e5a280ef0e87cfacd026",
   "gcr.io/fuzzbench/builders/afl/libxml2-v2.9.2":"sha256:3b4c79ed2f3174e635f9c9ad4d3a7d9c0b496c2ff3cd8e13480c687cc43e5a36",
   "gcr.io/fuzzbench/runners/afl/libxml2-v2.9.2-intermediate":"sha256:af6ef89dce3084ff3eccd97f93aa227f51d6104c77c5a500358f83d02d5e2122",
   "gcr.io/fuzzbench/runners/afl/libxml2-v2.9.2":"sha256:68620721229363905c3fea926d14fd0f8953aa0049c4d6048f2411e35ba026e6",
   "gcr.io/fuzzbench/builders/entropic/libxml2-v2.9.2-intermediate":"sha256:12a2771c05d40bbc7a18287fe4fccea1e80793542de47b0fe532a8dc43f7b998",
   "gcr.io/fuzzbench/builders/entropic/libxml2-v2.9.2":"sha256:11d980029123057c7fb2cd58d8a3373db8ce71cfb086611552b9389cfd0f41df",
   "gcr.io/fuzzbench/runners/entropic/libxml2-v2.9.2-intermediate":"sha256:af6ef89dce3084ff3eccd97f93aa227f51d6104c77c5a500358f83d02d5e2122",
   "gcr.io/fuzzbench/runners/entropic/libxml2-v2.9.2":"sha256:b4e15aed571e5fb8fb8cf52e6bd4abf3fffaacee8556ae5816672ccf2f744233",
   "gcr.io/fuzzbench/builders/libfuzzer/libxml2-v2.9.2-intermediate":"sha256:8cd100e4f1ec0e7cf7da0f9b9dff88f01ce2e308de60853c8fa6c42e28043ce2",
   "gcr.io/fuzzbench/builders/libfuzzer/libxml2-v2.9.2":"sha256:c61f84c22c30102fa6f18fa61699457237abf3b01ed6ebc9196637f1ec9ee4b4",
   "gcr.io/fuzzbench/runners/libfuzzer/libxml2-v2.9.2-intermediate":"sha256:af6ef89dce3084ff3eccd97f93aa227f51d6104c77c5a500358f83d02d5e2122",
   "gcr.io/fuzzbench/runners/libfuzzer/libxml2-v2.9.2":"sha256:025a77c0dcd4c8318ef5a43234fb37ee843cf3b506d5513b63793ec111daba91",
   "gcr.io/fuzzbench/builders/eclipser/libxml2-v2.9.2-intermediate":"sha256:31ddbfe5affc657d5551fd94ee32b5f147aae39806706a20ed6f2d26e27aeaf6",
   "gcr.io/fuzzbench/builders/eclipser/libxml2-v2.9.2":"sha256:d6299fb933f16ce16ce6458374b2c536b772ea3a69049ea313c3d66834e0b691",
   "gcr.io/fuzzbench/runners/eclipser/libxml2-v2.9.2-intermediate":"sha256:4140537ccd6b57009572153517b780bab03ddd7cffa41368394deebe5d908b04",
   "gcr.io/fuzzbench/runners/eclipser/libxml2-v2.9.2":"sha256:1a6ef9dc6c2fd0ec67a9dfe8cb1a4358ea17479567fd6fb8877b498a9bc57919",
   "gcr.io/fuzzbench/builders/benchmark/libxslt_xpath":"sha256:d6484d1bce80cdc2b6e1e526bfa9c5aaa4dd9cdc921e06f40a53ca20099709eb",
   "gcr.io/fuzzbench/builders/coverage/libxslt_xpath-intermediate":"sha256:ae8d16582d6bc9d200a56796f92c4deefacbede531e10b0896fcdd8402dc2eb6",
   "gcr.io/fuzzbench/builders/coverage/libxslt_xpath":"sha256:441f9e4065465abb5610c5ee68609c902293388904cee128a7b0dfbd83937abb",
   "gcr.io/fuzzbench/builders/honggfuzz/libxslt_xpath-intermediate":"sha256:32004e9cdcf95499ac22314eae1bab315ab2253b09f9dc9d2d01833b92082c13",
   "gcr.io/fuzzbench/builders/honggfuzz/libxslt_xpath":"sha256:da7cf406cc7b5fcd3a52aa2825c0c81a7a9faa0ac922950d33592c42bffcb00a",
   "gcr.io/fuzzbench/runners/honggfuzz/libxslt_xpath-intermediate":"sha256:d039730005ade48dbc7a27c4d95640d45a298bdc67c342accda585f4b895d640",
   "gcr.io/fuzzbench/runners/honggfuzz/libxslt_xpath":"sha256:3eeceb997db23c39667e8bc71e285ee480e876b89e0a482a53450c9ea3ea80a7",
   "gcr.io/fuzzbench/builders/aflplusplus/libxslt_xpath-intermediate":"sha256:de8c99dfcda390b762ea7955dc4619a4ff4dd62b232f4263c6818380005ed872",
   "gcr.io/fuzzbench/builders/aflplusplus/libxslt_xpath":"sha256:b9eac611cbc40599d00a16058b269415524560820d8510ce966bdbbe34fd84a7",
   "gcr.io/fuzzbench/runners/aflplusplus/libxslt_xpath-intermediate":"sha256:4017f2bd600a7729de9fb5e9df7ec7db845c1af17f8ce10f0107409851fe4b8f",
   "gcr.io/fuzzbench/runners/aflplusplus/libxslt_xpath":"sha256:052412576a21547f76a9059da0626f4fcaaa5724b2a9849da54cd16adee542d9",
   "gcr.io/fuzzbench/builders/afl/libxslt_xpath-intermediate":"sha256:69095301d86acaf7daca228c2a6ab17257bc2530371363a86294dfbefbbfc2a3",
   "gcr.io/fuzzbench/builders/afl/libxslt_xpath":"sha256:7f29d415da553db6eacd66da7bf2ff4e209ad6c6461bfab275c2e0c0656e328b",
   "gcr.io/fuzzbench/runners/afl/libxslt_xpath-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/afl/libxslt_xpath":"sha256:34d08629ac6f40b0675094ce081b8ff3596937fee092b27e5976eb912d71aee6",
   "gcr.io/fuzzbench/builders/entropic/libxslt_xpath-intermediate":"sha256:ae17c4611bd007b1ae33b4b832724f4b5ad5ea42ab95f74de485335eaa4d2f37",
   "gcr.io/fuzzbench/builders/entropic/libxslt_xpath":"sha256:e7d4d208b2314be2568b3f45717cba718169bd22078d31a728ecdc54ddeb8109",
   "gcr.io/fuzzbench/runners/entropic/libxslt_xpath-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/entropic/libxslt_xpath":"sha256:b474a5330caaa9b582ae0e32f176ff1c8e18b51689035b6e0d54e563aab9daca",
   "gcr.io/fuzzbench/builders/libfuzzer/libxslt_xpath-intermediate":"sha256:67a1e3e306846f5ff8fba260f6dda4f31807ab65a9ea029989ca212d0c5953bb",
   "gcr.io/fuzzbench/builders/libfuzzer/libxslt_xpath":"sha256:6eb37a370db56bca8a4a59ebd742f6c8572cb4e03184d7e28616cfa6900f4684",
   "gcr.io/fuzzbench/runners/libfuzzer/libxslt_xpath-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/libfuzzer/libxslt_xpath":"sha256:a7b2f6a031ea1ffdd5cfab415aa2ba6e771da9441faa5a0e759c666744c879df",
   "gcr.io/fuzzbench/builders/eclipser/libxslt_xpath-intermediate":"sha256:65efc20a42073e465beb16841752a52ce3cd23c721efbe213a9c31e604b16f22",
   "gcr.io/fuzzbench/builders/eclipser/libxslt_xpath":"sha256:05ac15d259be27e6308777ea893ff728e040648d1be43ce177ca01fc38d258e9",
   "gcr.io/fuzzbench/runners/eclipser/libxslt_xpath-intermediate":"sha256:0e22b551fd174100cf9e7e0ecd40d66ef6cb5c9d0149749d74dcfb6d5ddc30ce",
   "gcr.io/fuzzbench/runners/eclipser/libxslt_xpath":"sha256:c857242b9d91a7e5b9c7da56ecaa99e5428f4519ebee4ed5beff2134cfdc7a19",
   "gcr.io/fuzzbench/builders/benchmark/mbedtls_fuzz_dtlsclient":"sha256:2dff8d397b200622628797e17068132da1ac43436d875c72f7b1c1b609aa1db6",
   "gcr.io/fuzzbench/builders/coverage/mbedtls_fuzz_dtlsclient-intermediate":"sha256:b4dada049725207eaf3eef91286af2f2bcee27a58bf78c8036be6a5026fbef8c",
   "gcr.io/fuzzbench/builders/coverage/mbedtls_fuzz_dtlsclient":"sha256:2e611b96adbe5d382dd0d67ea611e450d067a840264d271e0829adab597a6c74",
   "gcr.io/fuzzbench/builders/honggfuzz/mbedtls_fuzz_dtlsclient-intermediate":"sha256:a97cb391efbc89b44340a26579e1a0f025bd5349937024db58a2b468adfcb113",
   "gcr.io/fuzzbench/builders/honggfuzz/mbedtls_fuzz_dtlsclient":"sha256:5aad42a483ab17157f8a6c7179133392a81ece7e1ee5004250b6c865fea2c91a",
   "gcr.io/fuzzbench/runners/honggfuzz/mbedtls_fuzz_dtlsclient-intermediate":"sha256:e733b03c050c74b02c5a98e08b4b6ad2ef8b5ee8c4bb8739b118efd69149eeb4",
   "gcr.io/fuzzbench/runners/honggfuzz/mbedtls_fuzz_dtlsclient":"sha256:98d97663a9555b94e6a1d1518f0d7ecd038cc8ad4b321d0e535a81929bf4ff6d",
   "gcr.io/fuzzbench/builders/aflplusplus/mbedtls_fuzz_dtlsclient-intermediate":"sha256:a361576f7bc8f9b183c3634c83117fb22869d05804580205b61814e3dd22aefc",
   "gcr.io/fuzzbench/builders/aflplusplus/mbedtls_fuzz_dtlsclient":"sha256:f053a4d735ac3c7ddd6c33bef300ca7604d734c7f4af11774e2eb0fc22ecdf89",
   "gcr.io/fuzzbench/runners/aflplusplus/mbedtls_fuzz_dtlsclient-intermediate":"sha256:4017f2bd600a7729de9fb5e9df7ec7db845c1af17f8ce10f0107409851fe4b8f",
   "gcr.io/fuzzbench/runners/aflplusplus/mbedtls_fuzz_dtlsclient":"sha256:2c0b395585da81ae6e82335a9f5662452b171e7217eca1876e429853c1c27765",
   "gcr.io/fuzzbench/builders/afl/mbedtls_fuzz_dtlsclient-intermediate":"sha256:997d5310fa89b1dc9fd3cc7813d98d56200d36801ea39bda5d0c0d88ae0b7528",
   "gcr.io/fuzzbench/builders/afl/mbedtls_fuzz_dtlsclient":"sha256:83fad632e717e14f4d1ef5640cc855afc6df6405276fdbc40a159ecf5b9a7cab",
   "gcr.io/fuzzbench/runners/afl/mbedtls_fuzz_dtlsclient-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/afl/mbedtls_fuzz_dtlsclient":"sha256:ff14ce80ea4230778c7077f63c2a9bd5f9bca63ca17ebbb79762c156660acabe",
   "gcr.io/fuzzbench/builders/entropic/mbedtls_fuzz_dtlsclient-intermediate":"sha256:ba40926f25d355ef2eb26a37d86d18b76c42c8fce726ee58b782054af5b5a483",
   "gcr.io/fuzzbench/builders/entropic/mbedtls_fuzz_dtlsclient":"sha256:1f92922fa28281412f1b0e01acdcc8a00c2b82bbedb69843299ccf7eb395db6d",
   "gcr.io/fuzzbench/runners/entropic/mbedtls_fuzz_dtlsclient-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/entropic/mbedtls_fuzz_dtlsclient":"sha256:94d68f1abb8d02df704464b996f8e185a16b5ec8c5614dfcd32226643db38e2f",
   "gcr.io/fuzzbench/builders/libfuzzer/mbedtls_fuzz_dtlsclient-intermediate":"sha256:4a4d3ddc7bededcbfc897d694643dc068976ac4c64a450a8cdc65900cf437e6d",
   "gcr.io/fuzzbench/builders/libfuzzer/mbedtls_fuzz_dtlsclient":"sha256:f49ff2be50818ee931217d5b855b59008dc99901501c33906db4a7b69f27bd48",
   "gcr.io/fuzzbench/runners/libfuzzer/mbedtls_fuzz_dtlsclient-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/libfuzzer/mbedtls_fuzz_dtlsclient":"sha256:292b43787e2e964c06ea851e1b1fc5da80223ff8134645cf798c4aa0e647a184",
   "gcr.io/fuzzbench/builders/eclipser/mbedtls_fuzz_dtlsclient-intermediate":"sha256:ca6aefbfa44c25727962d682f0135eb1b27b2e9d7c0f1b22065010cf372b6984",
   "gcr.io/fuzzbench/builders/eclipser/mbedtls_fuzz_dtlsclient":"sha256:29f251b14a82b250ee9109f3e2cd6edbc3b7824ec0ffaf74e38c88f4dea7593e",
   "gcr.io/fuzzbench/runners/eclipser/mbedtls_fuzz_dtlsclient-intermediate":"sha256:eeca46c72da5406ffa114f878c49462e319f6003d4f621f4bebfc32ee2857618",
   "gcr.io/fuzzbench/runners/eclipser/mbedtls_fuzz_dtlsclient":"sha256:b5bec1179b9029410893a4090306da37e7afd3e52f003a1c6a5ec0020aac0d63",
   "gcr.io/fuzzbench/builders/benchmark/openssl_x509":"sha256:3e3338e9df7917389b317e6d3dde6d8b22c8fdfff2fc52ba7d2fd339b9144894",
   "gcr.io/fuzzbench/builders/coverage/openssl_x509-intermediate":"sha256:38bd5cc0ed25eb52ebf87f46c4ccfb915f2917fc32a22942c318bde869a9ee36",
   "gcr.io/fuzzbench/builders/coverage/openssl_x509":"sha256:738887787f3b894f08232f45a3005adf17fc84140574b3c37d637a6f1c0c2bfd",
   "gcr.io/fuzzbench/builders/honggfuzz/openssl_x509-intermediate":"sha256:799c5b1ad7d1454eace66558f6ea2a005d881d68fc9430f63e6927105e2d826b",
   "gcr.io/fuzzbench/builders/honggfuzz/openssl_x509":"sha256:1d060dffaa9321aa0dbe6281daf2f90760471db51b036c5cf7699a9ea1f853ce",
   "gcr.io/fuzzbench/runners/honggfuzz/openssl_x509-intermediate":"sha256:1d57b4e72f8d6b92e7e60b9c3b260c869e4ac523b32f0e4ae149f2aec8dce01a",
   "gcr.io/fuzzbench/runners/honggfuzz/openssl_x509":"sha256:4122076841c104c23fb8bbd86922978177e58954e7fbb4cae1ab9fcea14c0d10",
   "gcr.io/fuzzbench/builders/aflplusplus/openssl_x509-intermediate":"sha256:cc03fe9627f8d79e7d3c842db27eb4cf71858df10fd61ceca50b1a1ad3e54ab2",
   "gcr.io/fuzzbench/builders/aflplusplus/openssl_x509":"sha256:fedda318143635c75e8864cb97fa6fc1bb58f558fa47ac55aacb33d1cffdc8ff",
   "gcr.io/fuzzbench/runners/aflplusplus/openssl_x509-intermediate":"sha256:4017f2bd600a7729de9fb5e9df7ec7db845c1af17f8ce10f0107409851fe4b8f",
   "gcr.io/fuzzbench/runners/aflplusplus/openssl_x509":"sha256:eea21b18c327d42135e2007032c4ee91524795949081c9fe6134192605e51b20",
   "gcr.io/fuzzbench/builders/afl/openssl_x509-intermediate":"sha256:634e51c0e79cd9569efc270bd0c47795d32dd5986306e3a3949157792ed6efa0",
   "gcr.io/fuzzbench/builders/afl/openssl_x509":"sha256:715fee3acac8583f1af21aa531bb5dd90d88c712b40bf10079f90bd567c3b476",
   "gcr.io/fuzzbench/runners/afl/openssl_x509-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/afl/openssl_x509":"sha256:afd219213c49c61f1229330ab2a1713e24506d608b98ba7fc1f22ca99249ecc5",
   "gcr.io/fuzzbench/builders/entropic/openssl_x509-intermediate":"sha256:2dfa5eed3f913d8abf7f2b911a4201ed390b95e168c72f3a3076e8ed82e2633d",
   "gcr.io/fuzzbench/builders/entropic/openssl_x509":"sha256:1f9c14bddc289686175e8b728c3997398329ccf6abde070af31b47880e27e065",
   "gcr.io/fuzzbench/runners/entropic/openssl_x509-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/entropic/openssl_x509":"sha256:ffb8c9faf48345fdc3aff3657d711fd92ebe039560e3a303bc4a7df8a5595782",
   "gcr.io/fuzzbench/builders/libfuzzer/openssl_x509-intermediate":"sha256:9f392328616a35e047d21cb584422f571d3d5f530080ff069c6edfc5126409be",
   "gcr.io/fuzzbench/builders/libfuzzer/openssl_x509":"sha256:8f258af3d4929cc18ebd21a4252e9074fb02268c35fb5e20f4f797c1eefd1738",
   "gcr.io/fuzzbench/runners/libfuzzer/openssl_x509-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/libfuzzer/openssl_x509":"sha256:22a12760fc44771f5fe0b5a3da626848add5770c47877d49d93941c99b93d540",
   "gcr.io/fuzzbench/builders/eclipser/openssl_x509-intermediate":"sha256:0cd0c777d3af0626718c712c25cd0711ed93e193bdcc0e331e3d4d9aca888d14",
   "gcr.io/fuzzbench/builders/eclipser/openssl_x509":"sha256:51f1e465bdc924de60c4ca56d7a6822c1c3f135091cf9b6451f6bbcb6ceb08da",
   "gcr.io/fuzzbench/runners/eclipser/openssl_x509-intermediate":"sha256:f7f6025a49201c36e19ae18dae4f92e69c5a3b1f9258aa1c2029fa33a641908b",
   "gcr.io/fuzzbench/runners/eclipser/openssl_x509":"sha256:7faad5b10d5ae5f6435e2d78f424799b1749106370ed01d62548b6b66f20041a",
   "gcr.io/fuzzbench/builders/benchmark/openthread-2019-12-23":"sha256:8e75dc65edfff08d2ea98bc9745faee1565db8490b64b1d15e5664693c08241b",
   "gcr.io/fuzzbench/builders/coverage/openthread-2019-12-23-intermediate":"sha256:a62721fdd3de7dbe9a00f0fd94c909f73537f7c02d222902e47946506334b45f",
   "gcr.io/fuzzbench/builders/coverage/openthread-2019-12-23":"sha256:984c86bd12bb2f45204714ab0e7c0de4d130a65408b00454549bafb166d18301",
   "gcr.io/fuzzbench/builders/honggfuzz/openthread-2019-12-23-intermediate":"sha256:54944504313dc854f99664cc02facacb3fd8b7f1f989b10cd990ac2868fee4fa",
   "gcr.io/fuzzbench/builders/honggfuzz/openthread-2019-12-23":"sha256:2e0baa1670ab01c92b1d28a539c8ac7a11db590277de778e1ee1a24a3ac745eb",
   "gcr.io/fuzzbench/runners/honggfuzz/openthread-2019-12-23-intermediate":"sha256:93b29e92ecb2d61b09329afe0ae4000e6de4a2f6aaca83bca3572ad85a0fa3b5",
   "gcr.io/fuzzbench/runners/honggfuzz/openthread-2019-12-23":"sha256:fa380050aefb14376f43adf1cd344cab5e9179c319a1a2f8419460b60de5b790",
   "gcr.io/fuzzbench/builders/aflplusplus/openthread-2019-12-23-intermediate":"sha256:b6df3a48eda5f24812616ef44ccfd54226649bb078a0ff2596ae2ef002ae4b42",
   "gcr.io/fuzzbench/builders/aflplusplus/openthread-2019-12-23":"sha256:464d7032d0deedf91c812d57441dbe7cc95b85252b8d7f98158196d986b42521",
   "gcr.io/fuzzbench/runners/aflplusplus/openthread-2019-12-23-intermediate":"sha256:4017f2bd600a7729de9fb5e9df7ec7db845c1af17f8ce10f0107409851fe4b8f",
   "gcr.io/fuzzbench/runners/aflplusplus/openthread-2019-12-23":"sha256:b6942ef770fcaf42bdf11c8e92d1cd5b9a735a03bff80489627563c1e5c7b965",
   "gcr.io/fuzzbench/builders/afl/openthread-2019-12-23-intermediate":"sha256:c2dd583a86a306c17b36ce4f51c3fba4d63dc71aafe4634b8592935cc5b38cb1",
   "gcr.io/fuzzbench/builders/afl/openthread-2019-12-23":"sha256:c93ba334ec3ccf19dc1934a94d85d031ccfeffcb667a8363d7f2043328e54356",
   "gcr.io/fuzzbench/runners/afl/openthread-2019-12-23-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/afl/openthread-2019-12-23":"sha256:d5e6ea1484b005bbcd16568c24c0676a49ce1ebd58c8a5b81a929bd5a85bad15",
   "gcr.io/fuzzbench/builders/entropic/openthread-2019-12-23-intermediate":"sha256:f8db2bb8103625e21bd26c2fdbfdad880a57d8d3c1f7579ed9722f9663297dd8",
   "gcr.io/fuzzbench/builders/entropic/openthread-2019-12-23":"sha256:b27a1c56395356f5db1a6a509f16d2c16b468a1968796d3827fa470e689752d0",
   "gcr.io/fuzzbench/runners/entropic/openthread-2019-12-23-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/entropic/openthread-2019-12-23":"sha256:17ec4ed079dc28227bcded6e10a3fb23d40f9460750b4023ec9ddff9df9fe76b",
   "gcr.io/fuzzbench/builders/libfuzzer/openthread-2019-12-23-intermediate":"sha256:04be36c457f83b8784fbea71da5f4fec016469d6133dcd6e65f04cb8856e9dd7",
   "gcr.io/fuzzbench/builders/libfuzzer/openthread-2019-12-23":"sha256:8dd45490a84c0ef572a8dacc7cd8c0bd7ea623731a363f272d18f7605b5642e1",
   "gcr.io/fuzzbench/runners/libfuzzer/openthread-2019-12-23-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/libfuzzer/openthread-2019-12-23":"sha256:6e1941f13cb3c3931d0632dc5289474e41f14e936f71acc80ad53360917b6a5d",
   "gcr.io/fuzzbench/builders/eclipser/openthread-2019-12-23-intermediate":"sha256:a5eb29bebf7126ebe1ab4bad337cc41596f144e0a2a9c0d61e053f5b0fed3113",
   "gcr.io/fuzzbench/builders/eclipser/openthread-2019-12-23":"sha256:41c54e7bf6e1612353e41e55cc1d824d6c7b88b9d27ad8b04a73e86b680845aa",
   "gcr.io/fuzzbench/runners/eclipser/openthread-2019-12-23-intermediate":"sha256:3b29d0dedfcb835f9c303bb3af4e5b61a6b329882c50ebdef1495dd1df2fe1fd",
   "gcr.io/fuzzbench/runners/eclipser/openthread-2019-12-23":"sha256:7ea564546985cea0d356141596638910ee562794bf8152d11e5db56b8d2d6039",
   "gcr.io/fuzzbench/builders/benchmark/php_php-fuzz-parser":"sha256:3fabfa19f5ff5cfc90f7d72ee2c1a00cc546c55742ad363a72da47e9e850ee46",
   "gcr.io/fuzzbench/builders/coverage/php_php-fuzz-parser-intermediate":"sha256:e87427c0b5776a1d3b79253717cb60bc88ca1552df91baf3a7bf6965fa1f1c52",
   "gcr.io/fuzzbench/builders/coverage/php_php-fuzz-parser":"sha256:9d659afb2f786bc4746533f6a4f4e8d7ab53d42d073a0f432a5c1f0eeab2b701",
   "gcr.io/fuzzbench/builders/honggfuzz/php_php-fuzz-parser-intermediate":"sha256:a4ad89cec03de63a74e36a53c34a704a9870d79d1b7dabe95e1003ceff7edcb9",
   "gcr.io/fuzzbench/builders/honggfuzz/php_php-fuzz-parser":"sha256:1c97437cc1952f885cbf50c13d240ef0923a346d2662fa82076e8a7e690d89ab",
   "gcr.io/fuzzbench/runners/honggfuzz/php_php-fuzz-parser-intermediate":"sha256:95188ef7a5ec419831a7943cf658d17b960c338f47123421b5c0e83bd93d1bfd",
   "gcr.io/fuzzbench/runners/honggfuzz/php_php-fuzz-parser":"sha256:f563a2f96b40beb003ba9a0a03e38dc459bd710531517ccd906b45761d637edc",
   "gcr.io/fuzzbench/builders/aflplusplus/php_php-fuzz-parser-intermediate":"sha256:ab1b26d574604e8c81100bc217098066c39f22e75c6c231cc9a866a05ae6f6b9",
   "gcr.io/fuzzbench/builders/aflplusplus/php_php-fuzz-parser":"sha256:1ba9baa52407e26865d1d6e5b98511d25a9c1575984377f5a888fd21995f2291",
   "gcr.io/fuzzbench/runners/aflplusplus/php_php-fuzz-parser-intermediate":"sha256:4017f2bd600a7729de9fb5e9df7ec7db845c1af17f8ce10f0107409851fe4b8f",
   "gcr.io/fuzzbench/runners/aflplusplus/php_php-fuzz-parser":"sha256:2ed3eb9db2330105c0e4a24dda2413c36fda16349b306f9f7e14806cb4ffca6b",
   "gcr.io/fuzzbench/builders/afl/php_php-fuzz-parser-intermediate":"sha256:d6de5855822ac0a25ea513284cf70c349041016eb630cec4deb0b1bd813ea303",
   "gcr.io/fuzzbench/builders/afl/php_php-fuzz-parser":"sha256:89961d74e769e0023834b2aec97874f1fa64daee6450f5ac484cabb3662f6cfa",
   "gcr.io/fuzzbench/runners/afl/php_php-fuzz-parser-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/afl/php_php-fuzz-parser":"sha256:fe9f14e70f4a80d9b6c17d6bfa6317aaca5813247422689962703ef938fc4507",
   "gcr.io/fuzzbench/builders/entropic/php_php-fuzz-parser-intermediate":"sha256:ab6547d20d266bc0a5826648aa6833ddd13b662d4a03a7749f36a8cb342e38b7",
   "gcr.io/fuzzbench/builders/entropic/php_php-fuzz-parser":"sha256:f42b7c5e424efbadfddd8df562002a2f4cf1abe7ca1a21d020ebb0f5da06c80b",
   "gcr.io/fuzzbench/runners/entropic/php_php-fuzz-parser-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/entropic/php_php-fuzz-parser":"sha256:6f368ba34e0f374f6b369c487e44213a3dae7443830f93ffe9186e61c6a20a5a",
   "gcr.io/fuzzbench/builders/libfuzzer/php_php-fuzz-parser-intermediate":"sha256:0dde5903cad950b01e8c95c3344ba411936de6e72c5046884018b6fcd56e4426",
   "gcr.io/fuzzbench/builders/libfuzzer/php_php-fuzz-parser":"sha256:d81340809d4a98a0ec945de2ee076ea55d814ca5e9902cdbeeef95da3d964c96",
   "gcr.io/fuzzbench/runners/libfuzzer/php_php-fuzz-parser-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/libfuzzer/php_php-fuzz-parser":"sha256:38890fef1bef317182c7244d1ba2daece29d2044def1686d8514924c14623792",
   "gcr.io/fuzzbench/builders/eclipser/php_php-fuzz-parser-intermediate":"sha256:06dfef39abf6ff0f04726b07f4e7e454709355df54fafd3ea6f8df2a38ace0db",
   "gcr.io/fuzzbench/builders/eclipser/php_php-fuzz-parser":"sha256:4971b30f40982a716879a9b2b1d7619dc2831cadcdb1297d78dbd35964f6e086",
   "gcr.io/fuzzbench/runners/eclipser/php_php-fuzz-parser-intermediate":"sha256:836e262c853d577950cb5a3de8307e3135fa7d6eb3ce7bf58ffd343a24d1e515",
   "gcr.io/fuzzbench/runners/eclipser/php_php-fuzz-parser":"sha256:0679e5bd82976e98cebe2dc0b68bb91c01ccef376e49d9ddb932222f61692631",
   "gcr.io/fuzzbench/builders/benchmark/proj4-2017-08-14":"sha256:5b6d8f30ef309569dc32b8aab37cafc4aed8cb0e23d306b1e0fe35e46a315891",
   "gcr.io/fuzzbench/builders/coverage/proj4-2017-08-14-intermediate":"sha256:9129461a2f7b4dd22168465184bd4c3e2161cc80c1732f3e3fe8ecfc581d25ef",
   "gcr.io/fuzzbench/builders/coverage/proj4-2017-08-14":"sha256:32551acd49c0577e50e3cbb50fcc8b703779bcc5493a4f5f08d512115d5edafe",
   "gcr.io/fuzzbench/builders/honggfuzz/proj4-2017-08-14-intermediate":"sha256:04d4354ca2e0929cd748f726ffbc11b14be8c5e72ac07a5dc676ee2ea9b6309b",
   "gcr.io/fuzzbench/builders/honggfuzz/proj4-2017-08-14":"sha256:ed4635d550366f46fa203918b9fd9049ab86b1359b2e7d94277004604f65f152",
   "gcr.io/fuzzbench/runners/honggfuzz/proj4-2017-08-14-intermediate":"sha256:aff9cf2f83ee218a9985c3160f31f8ed55e548fb8a91f7f187e600ba7eac7c5f",
   "gcr.io/fuzzbench/runners/honggfuzz/proj4-2017-08-14":"sha256:f6e0fedd07585d238a053717a55c0b386f7ddea5bb57828c288409d645821369",
   "gcr.io/fuzzbench/builders/aflplusplus/proj4-2017-08-14-intermediate":"sha256:f51166ba30535718e74dbc75f93e55953968e23a1f66640b132e0d515edae72b",
   "gcr.io/fuzzbench/builders/aflplusplus/proj4-2017-08-14":"sha256:97f3e1d004c33839053521c9d9a7c5b6abae2a8a240578f31469563b6c8f975f",
   "gcr.io/fuzzbench/runners/aflplusplus/proj4-2017-08-14-intermediate":"sha256:4017f2bd600a7729de9fb5e9df7ec7db845c1af17f8ce10f0107409851fe4b8f",
   "gcr.io/fuzzbench/runners/aflplusplus/proj4-2017-08-14":"sha256:7b2ffa3956cd75d3e5551268b371590dad3d336477084454ae84ecb6094c76e5",
   "gcr.io/fuzzbench/builders/afl/proj4-2017-08-14-intermediate":"sha256:37cb6af8d44326e49267756f0939e121d3479799ff875adbbdf5d082f23c14e6",
   "gcr.io/fuzzbench/builders/afl/proj4-2017-08-14":"sha256:bc903da5855a5def8c007f9749652e11a05b1e1ea08364e60dbf25a4cb63ed3e",
   "gcr.io/fuzzbench/runners/afl/proj4-2017-08-14-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/afl/proj4-2017-08-14":"sha256:dd0f7b194562b5959fb2f34b4248c84a757562f30c7a811805b90f8d48043642",
   "gcr.io/fuzzbench/builders/entropic/proj4-2017-08-14-intermediate":"sha256:35e3d5ef62d04de13f28d5c10ee5ecca8c603098e1d0995ef89c31dbf1c426fa",
   "gcr.io/fuzzbench/builders/entropic/proj4-2017-08-14":"sha256:3f8b9327494327d8e412431d1faeb32551aa3616a5db7b4a239943a91d4ade9a",
   "gcr.io/fuzzbench/runners/entropic/proj4-2017-08-14-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/entropic/proj4-2017-08-14":"sha256:777e97617c3721f94096f78fda52a7d90ccb08a38a96884a2e4fd078ef0b2169",
   "gcr.io/fuzzbench/builders/libfuzzer/proj4-2017-08-14-intermediate":"sha256:c9dac77d98bc3e9885c3fe76cd0891184299566652f7ec7db0a569ac9c57382b",
   "gcr.io/fuzzbench/builders/libfuzzer/proj4-2017-08-14":"sha256:7bc7baa67cd86b2fa449043947bfae4029fe466085b5cb515170cb5f32473d0e",
   "gcr.io/fuzzbench/runners/libfuzzer/proj4-2017-08-14-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/libfuzzer/proj4-2017-08-14":"sha256:6cf8373a98c861349407fbc87eac1822ca6ba52cd7441b520abc71a16e575a02",
   "gcr.io/fuzzbench/builders/eclipser/proj4-2017-08-14-intermediate":"sha256:9f90b727383b3bb3baf8850bef38de5396b47c192d393bb6844ae1c53c9a9184",
   "gcr.io/fuzzbench/builders/eclipser/proj4-2017-08-14":"sha256:923f315f4245386bb39a2369925fa1941bfb838df07a1c710624a1fd39299982",
   "gcr.io/fuzzbench/runners/eclipser/proj4-2017-08-14-intermediate":"sha256:e066a16aa68d29caa84dd3471e6e05e90e11948e020be0f3a6bdc10dd25413d3",
   "gcr.io/fuzzbench/runners/eclipser/proj4-2017-08-14":"sha256:5fcb7b10dff2efa43433f74470911680280fd51bb8839a02100daba34ae5a2f8",
   "gcr.io/fuzzbench/builders/benchmark/re2-2014-12-09":"sha256:a163208f16c299e7a169bc0c65a2fe1860cd6aebf0baa6e1d57aaa48242bf1b4",
   "gcr.io/fuzzbench/builders/coverage/re2-2014-12-09-intermediate":"sha256:30d9526c30ed55d142871e05700474ac9eb115563a287f76669e99ba7a9f5a83",
   "gcr.io/fuzzbench/builders/coverage/re2-2014-12-09":"sha256:75e4300028822824951896a3a3a3118e72c7a3f6968a6b8f4f8fed412acc89f4",
   "gcr.io/fuzzbench/builders/honggfuzz/re2-2014-12-09-intermediate":"sha256:b71b8ebc86b17f045cd1284ce5d669eb8aa5f149210e29912661ec5594bb3556",
   "gcr.io/fuzzbench/builders/honggfuzz/re2-2014-12-09":"sha256:77f687dba1a597edd31824d4272e57b8692b4ae014693858325e5969fc38601c",
   "gcr.io/fuzzbench/runners/honggfuzz/re2-2014-12-09-intermediate":"sha256:8cbb388ce2f47b98b7f8afaa907f75e796ce71e10d5ccc0dc15fe8f6cb1548b1",
   "gcr.io/fuzzbench/runners/honggfuzz/re2-2014-12-09":"sha256:9429cd749bd04eaf9924be8243d08c50b665091f2524ff91f00b9fae66950611",
   "gcr.io/fuzzbench/builders/aflplusplus/re2-2014-12-09-intermediate":"sha256:c833cceee96e2bcfc5b2c5ac4d201472f64cf0adbacbcb242c936d0cd5da9aae",
   "gcr.io/fuzzbench/builders/aflplusplus/re2-2014-12-09":"sha256:45082ccbdc7d78051c7fdc4522a3c2ebc2375061977242613dc9c4c1d42cfca3",
   "gcr.io/fuzzbench/runners/aflplusplus/re2-2014-12-09-intermediate":"sha256:cfbc1d44c388d6af98f5ec467aab8497b45279002e71c700f51ef0b4de05cd28",
   "gcr.io/fuzzbench/runners/aflplusplus/re2-2014-12-09":"sha256:372272ca9f9a97e6dbfbbbf1ab7c127a329ce0a32fb84d20b11c65dc2737faba",
   "gcr.io/fuzzbench/builders/afl/re2-2014-12-09-intermediate":"sha256:fa0f7ae9e86d50e6afe1e55ae3791d03fb97c3a7d62b30e8a7246a077de75290",
   "gcr.io/fuzzbench/builders/afl/re2-2014-12-09":"sha256:c463d7803c361ce0c00fcc1eefffbbca44b80ccbf70531d8cf74fcdd132004a4",
   "gcr.io/fuzzbench/runners/afl/re2-2014-12-09-intermediate":"sha256:af6ef89dce3084ff3eccd97f93aa227f51d6104c77c5a500358f83d02d5e2122",
   "gcr.io/fuzzbench/runners/afl/re2-2014-12-09":"sha256:a689ac8ee3463b4685945e243f1b1757ca8547d09489d4df4069ede1261ef3b6",
   "gcr.io/fuzzbench/builders/entropic/re2-2014-12-09-intermediate":"sha256:48d0aeff22c183eb09b7103547bc429a5ee754ca905712807abc1476477ec75f",
   "gcr.io/fuzzbench/builders/entropic/re2-2014-12-09":"sha256:f6bee4be5ccffa200b6c4e86bee0f7e67bb38f5edbcc22e1b54371480f3d77f9",
   "gcr.io/fuzzbench/runners/entropic/re2-2014-12-09-intermediate":"sha256:af6ef89dce3084ff3eccd97f93aa227f51d6104c77c5a500358f83d02d5e2122",
   "gcr.io/fuzzbench/runners/entropic/re2-2014-12-09":"sha256:f913f77d9b2c0f20434239f9bfbddbd6fa8e242d126855e3fc1e537a30dcf8bc",
   "gcr.io/fuzzbench/builders/libfuzzer/re2-2014-12-09-intermediate":"sha256:f4a63c5a69052bd51947b88556590cbbd22a63906d55f8566a2b89191bf08ba8",
   "gcr.io/fuzzbench/builders/libfuzzer/re2-2014-12-09":"sha256:b0e9f0400037bbc826b97ad64158467f5e50bd427985ac38b1221872bb241a02",
   "gcr.io/fuzzbench/runners/libfuzzer/re2-2014-12-09-intermediate":"sha256:af6ef89dce3084ff3eccd97f93aa227f51d6104c77c5a500358f83d02d5e2122",
   "gcr.io/fuzzbench/runners/libfuzzer/re2-2014-12-09":"sha256:73d2ac9fd0d4ca7e8d34be4f764e8cb61f7ef30fdc27e5285bdaaaab52fdf2c4",
   "gcr.io/fuzzbench/builders/eclipser/re2-2014-12-09-intermediate":"sha256:8bf468dfcf5db34fcfa06ef7adcbeedd023c946e4a11b54b2418d89cc0d6010c",
   "gcr.io/fuzzbench/builders/eclipser/re2-2014-12-09":"sha256:9cb85ef06f9d6149539639e453db1142ad25f9c56a3060a4297f9434aafea80b",
   "gcr.io/fuzzbench/runners/eclipser/re2-2014-12-09-intermediate":"sha256:334a347f21803574c572ef341a2937c4a93f77fc1c2ab5c6f2ea23bd5c14b380",
   "gcr.io/fuzzbench/runners/eclipser/re2-2014-12-09":"sha256:e37a8f81c8bc594be683af44831ab6dff6d26748116f327de74ec31617b83358",
   "gcr.io/fuzzbench/builders/benchmark/sqlite3_ossfuzz":"sha256:1ad68b87a959949f0c36dde620deb70c2a4741807013080f9f1193b1418285f6",
   "gcr.io/fuzzbench/builders/coverage/sqlite3_ossfuzz-intermediate":"sha256:96cce86826c056be6c9c2cbd842aeaa24b0b933d1a97a7624f8b36da98685cdc",
   "gcr.io/fuzzbench/builders/coverage/sqlite3_ossfuzz":"sha256:255e8b537f1ff75b1bf07647d1a8e726781766d4b8e9605cfa198f5825b1a6aa",
   "gcr.io/fuzzbench/builders/honggfuzz/sqlite3_ossfuzz-intermediate":"sha256:6415cd35c7f6ed93481c20d6ecb1c9114299fe0e1bbf6d034a12af85e92c554c",
   "gcr.io/fuzzbench/builders/honggfuzz/sqlite3_ossfuzz":"sha256:e130c8665f0a2cbb12177a575b25fa69e04c92cece32565550727e2ede94eba7",
   "gcr.io/fuzzbench/runners/honggfuzz/sqlite3_ossfuzz-intermediate":"sha256:e4d996bc42f8b76ff76f2481193db9f73c199a60500f8c4704e76f7d5d73395b",
   "gcr.io/fuzzbench/runners/honggfuzz/sqlite3_ossfuzz":"sha256:344db62b3cf0612f7ee73b7ee8c97f0b0af4607b653a12e67a7674905d634383",
   "gcr.io/fuzzbench/builders/aflplusplus/sqlite3_ossfuzz-intermediate":"sha256:ce829d41a68c112387fee3966dc47bb1a1347d8d626c9eaca21a2a1b2ddc44f5",
   "gcr.io/fuzzbench/builders/aflplusplus/sqlite3_ossfuzz":"sha256:41bab08273043e3da7ff4f660b7bad9cd91f07d516b1126daa105b73a416572b",
   "gcr.io/fuzzbench/runners/aflplusplus/sqlite3_ossfuzz-intermediate":"sha256:4017f2bd600a7729de9fb5e9df7ec7db845c1af17f8ce10f0107409851fe4b8f",
   "gcr.io/fuzzbench/runners/aflplusplus/sqlite3_ossfuzz":"sha256:8d07cc60c0c558df0a0b257d60d9a6216c7a85919ec7b395440120f3bea3931f",
   "gcr.io/fuzzbench/builders/afl/sqlite3_ossfuzz-intermediate":"sha256:64311bda637dae44b2ad5f4121ddd9f7c20976a1f2ccdc655560785365b305b6",
   "gcr.io/fuzzbench/builders/afl/sqlite3_ossfuzz":"sha256:1f00046fd7b2f7d6700f4cd445d1f4944682f32c8b03d9f50f1d2cb2bc5f3154",
   "gcr.io/fuzzbench/runners/afl/sqlite3_ossfuzz-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/afl/sqlite3_ossfuzz":"sha256:2451ccdec7f3f1581eb5cc56659ca5f6a2ea13b55c0324c137dc222d438eed31",
   "gcr.io/fuzzbench/builders/entropic/sqlite3_ossfuzz-intermediate":"sha256:5d0fb956c5b9eca1b4f3887b5c11ddc7325aa3587b3f15917ce0ebfd35d281da",
   "gcr.io/fuzzbench/builders/entropic/sqlite3_ossfuzz":"sha256:27b988da586beeb0bd2dbe830ff2e35909effec500629134bfc2cd2d54588b1d",
   "gcr.io/fuzzbench/runners/entropic/sqlite3_ossfuzz-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/entropic/sqlite3_ossfuzz":"sha256:b906c095f51aea39fa0310056a23556f489aef788f7b4671fcbcbf58226693ed",
   "gcr.io/fuzzbench/builders/libfuzzer/sqlite3_ossfuzz-intermediate":"sha256:bdf89c10aa45c73954296303942ca617f8dc6037a11fe21815de8932ad11c7ef",
   "gcr.io/fuzzbench/builders/libfuzzer/sqlite3_ossfuzz":"sha256:67081c9fd83cd487935b3e314ff68175195643e55a6d580656544eb2527a0d29",
   "gcr.io/fuzzbench/runners/libfuzzer/sqlite3_ossfuzz-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/libfuzzer/sqlite3_ossfuzz":"sha256:19995575afc10a1e02869c2a4dee281cae069591b79347ab3b8b1d8e783d5a49",
   "gcr.io/fuzzbench/builders/eclipser/sqlite3_ossfuzz-intermediate":"sha256:9c37c5eb6e3c172fd2f1ee8554464a273279b98a65553d39f9360aec572a3bf5",
   "gcr.io/fuzzbench/builders/eclipser/sqlite3_ossfuzz":"sha256:57c56af2e0822c03b252ac5e9928ec2c08959879df0a99fb75fdffaf5ac725f3",
   "gcr.io/fuzzbench/runners/eclipser/sqlite3_ossfuzz-intermediate":"sha256:5ee681a1c25c4ad439ab5c72a60bb682fe6ed1d149020e3f9656d9d110550e18",
   "gcr.io/fuzzbench/runners/eclipser/sqlite3_ossfuzz":"sha256:3ec4c2d4af35ed0bc21717a0ab0c47e0aa7d6ae377e12eb99452c364b12497ef",
   "gcr.io/fuzzbench/builders/benchmark/systemd_fuzz-link-parser":"sha256:461cf2c741535ac062c51bd933f3d9fdb0930bbd1f2f5cef8f513e4ccbc072bf",
   "gcr.io/fuzzbench/builders/coverage/systemd_fuzz-link-parser-intermediate":"sha256:e131aa6ae504e19a2089e6e02245da35a5371c7100f78e156b8f45a23ba19255",
   "gcr.io/fuzzbench/builders/coverage/systemd_fuzz-link-parser":"sha256:4b17f8948c4676e5e8b5ba26c7642a4fda4e1373230f6ffb1b7e4aa7324e9cc3",
   "gcr.io/fuzzbench/builders/honggfuzz/systemd_fuzz-link-parser-intermediate":"sha256:6b4c580493d082e04630e3168fdcabc2b64cea3523867e9d936713597378b4ec",
   "gcr.io/fuzzbench/builders/honggfuzz/systemd_fuzz-link-parser":"sha256:f99e8bfafd4a0697cb51d4d8a9b2bc0438fee18536cc92a603ab5055de1dedb8",
   "gcr.io/fuzzbench/runners/honggfuzz/systemd_fuzz-link-parser-intermediate":"sha256:3bec13c4adcb927e3c11705700214fe08a6c043c40674a33805a9656f8e00016",
   "gcr.io/fuzzbench/runners/honggfuzz/systemd_fuzz-link-parser":"sha256:d6be8cc464e95c15dfaff08aaca2c0a474ac25845269102409782ad31508b4bb",
   "gcr.io/fuzzbench/builders/aflplusplus/systemd_fuzz-link-parser-intermediate":"sha256:b07c0058dc73d99e3483a5d811b09e62c23ca88184c880072024e7328031dfaa",
   "gcr.io/fuzzbench/builders/aflplusplus/systemd_fuzz-link-parser":"sha256:23a785df4cfdec95be1c4fc78b8f5322385d5443765a626127afe38029f1e31f",
   "gcr.io/fuzzbench/runners/aflplusplus/systemd_fuzz-link-parser-intermediate":"sha256:4017f2bd600a7729de9fb5e9df7ec7db845c1af17f8ce10f0107409851fe4b8f",
   "gcr.io/fuzzbench/runners/aflplusplus/systemd_fuzz-link-parser":"sha256:2ce90cd572127291c5723b91fdd6e64ff8cb84411b2dcbf365e7492c79f359fd",
   "gcr.io/fuzzbench/builders/afl/systemd_fuzz-link-parser-intermediate":"sha256:069a8a5f426b47ceb48b9e67e44ea8e072e517dff8bb90fa0ea9bf829dcacf00",
   "gcr.io/fuzzbench/builders/afl/systemd_fuzz-link-parser":"sha256:34870d7b52207897108b04810bb1f3ef8814a3964ac856438306f1c204229bc6",
   "gcr.io/fuzzbench/runners/afl/systemd_fuzz-link-parser-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/afl/systemd_fuzz-link-parser":"sha256:41e8532320218690c9fc12a98c5dccda4a950e748ecc2e79eb2e72b008bdb7a2",
   "gcr.io/fuzzbench/builders/entropic/systemd_fuzz-link-parser-intermediate":"sha256:ffe883f5f0db19b49fe1cd8687bf440a755480e1567519f27060087aad848c7d",
   "gcr.io/fuzzbench/builders/entropic/systemd_fuzz-link-parser":"sha256:bec8350764047669c0a959cba4c99b8ab68738ed2e19d6e374a16dfbaa43ca22",
   "gcr.io/fuzzbench/runners/entropic/systemd_fuzz-link-parser-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/entropic/systemd_fuzz-link-parser":"sha256:c31f23074606308aa48117ebf819301927e96dcb5e474325abb936ae670337cb",
   "gcr.io/fuzzbench/builders/libfuzzer/systemd_fuzz-link-parser-intermediate":"sha256:6fe3f6382361fcdd8f8d30d005f874199727bc6f491864bc73bd8fdd66ccde18",
   "gcr.io/fuzzbench/builders/libfuzzer/systemd_fuzz-link-parser":"sha256:15c5f9ba971ec8bb019210e647531530d4fa6f6e8ca261036abad1973b436a4f",
   "gcr.io/fuzzbench/runners/libfuzzer/systemd_fuzz-link-parser-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/libfuzzer/systemd_fuzz-link-parser":"sha256:ef496ace3bd759f16928cd655ea4659e11db226206d5180c98ace95ee9cce5c1",
   "gcr.io/fuzzbench/builders/eclipser/systemd_fuzz-link-parser-intermediate":"sha256:e5528386eb44cadc3a9ad3815bde220ce0d9f32efa97312cee5fc3f0b177897d",
   "gcr.io/fuzzbench/builders/eclipser/systemd_fuzz-link-parser":"sha256:30630558f2058b0c02e0b92111e426f82a642f5fe73d44208683aeb64baca4e0",
   "gcr.io/fuzzbench/runners/eclipser/systemd_fuzz-link-parser-intermediate":"sha256:76fe6c44a30cd098f7b098aba0b96b8b94f3af0d6fcb28616f271426f4462e28",
   "gcr.io/fuzzbench/runners/eclipser/systemd_fuzz-link-parser":"sha256:b0baad722a0c19228308859a597ca9d37c5ccd8d4d479b4c84c50b3f4ca96b5e",
   "gcr.io/fuzzbench/builders/benchmark/vorbis-2017-12-11":"sha256:e5e17b50b334aabc7fddaa941dd14446492e7379c4f619d31baedb69674ec1dd",
   "gcr.io/fuzzbench/builders/coverage/vorbis-2017-12-11-intermediate":"sha256:2d7bb2f93f88ae137585cb1d1cbec8fd71805a774e419c10e2d42d73cca0cf1d",
   "gcr.io/fuzzbench/builders/coverage/vorbis-2017-12-11":"sha256:8c2c1b9cc8f8c4f66e0a4619fc364532d52d84fbf0cffb18ee3494fc83ac413a",
   "gcr.io/fuzzbench/builders/honggfuzz/vorbis-2017-12-11-intermediate":"sha256:99ef0ffd9be7ec2c16100c09f87bfa4e38e2d17987a5c33bf9de904f9909f37a",
   "gcr.io/fuzzbench/builders/honggfuzz/vorbis-2017-12-11":"sha256:1212a3158f738992bfdeba2da02c9cdd8b6628a31fb229d97d440b2767dbfa8a",
   "gcr.io/fuzzbench/runners/honggfuzz/vorbis-2017-12-11-intermediate":"sha256:438bc93801a1d0c313ec94ca86b66455a5696506d749d3eff3e1377816bb033c",
   "gcr.io/fuzzbench/runners/honggfuzz/vorbis-2017-12-11":"sha256:d0bf7fb72e4d426181f8ebffcccdf5f8f73411dbd23f3925152c91f61f83c3db",
   "gcr.io/fuzzbench/builders/aflplusplus/vorbis-2017-12-11-intermediate":"sha256:5ba8a0ad22101943a79f098e9196f3acbcbe3bdfd360bc67c0eeaa12e4876eed",
   "gcr.io/fuzzbench/builders/aflplusplus/vorbis-2017-12-11":"sha256:46eeb4dbcaf93ea67982aa1a5cb9f8b9b1a2745fcef9a7727b13e99d9a882980",
   "gcr.io/fuzzbench/runners/aflplusplus/vorbis-2017-12-11-intermediate":"sha256:4017f2bd600a7729de9fb5e9df7ec7db845c1af17f8ce10f0107409851fe4b8f",
   "gcr.io/fuzzbench/runners/aflplusplus/vorbis-2017-12-11":"sha256:41cc510a02ceb0578070cba4a428dc4826bed53e262876e53a11e580366f83fc",
   "gcr.io/fuzzbench/builders/afl/vorbis-2017-12-11-intermediate":"sha256:c8fca746d9eba577b586255970809c6cdd60636d406ac93fc5f0354e47000e3b",
   "gcr.io/fuzzbench/builders/afl/vorbis-2017-12-11":"sha256:25429ed0d3edde6b519755ba8fecbf95928c3b849ce0fd8ca65820051da55ee0",
   "gcr.io/fuzzbench/runners/afl/vorbis-2017-12-11-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/afl/vorbis-2017-12-11":"sha256:a1213a4b3fcd48f5b62f643ef9af06242a86c3a5656b9c91cdbff1ad7e0d8965",
   "gcr.io/fuzzbench/builders/entropic/vorbis-2017-12-11-intermediate":"sha256:acb59ec14a3397489e35f6c829d9c1ba468be2d789a34c5348d69b4994d56485",
   "gcr.io/fuzzbench/builders/entropic/vorbis-2017-12-11":"sha256:bf31d1015591ea5ad827203348ec486af0edf8ecb788163eb8559219e666f776",
   "gcr.io/fuzzbench/runners/entropic/vorbis-2017-12-11-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/entropic/vorbis-2017-12-11":"sha256:b221834d92eedf5eb44b0ad9bb2b0b5a7aaa89258468c4094f82001f9a1d4978",
   "gcr.io/fuzzbench/builders/libfuzzer/vorbis-2017-12-11-intermediate":"sha256:65be87c9759c95958520616b4ebff88793f90fc81b728967448af870d4b88669",
   "gcr.io/fuzzbench/builders/libfuzzer/vorbis-2017-12-11":"sha256:422b43ae0cb126452ddee3516705965804ac2e17c31adf5f3c9e6cbf2d48c342",
   "gcr.io/fuzzbench/runners/libfuzzer/vorbis-2017-12-11-intermediate":"sha256:c8e0cfa880fd3112efb034cf62bd18883268db5e475b2d5daaa5f24ae1a12caf",
   "gcr.io/fuzzbench/runners/libfuzzer/vorbis-2017-12-11":"sha256:7fe93666e789a9f91f89baca45def90a99a558b482b748b46c932d6b19e3c2e5",
   "gcr.io/fuzzbench/builders/eclipser/vorbis-2017-12-11-intermediate":"sha256:818281b0c091e5134cbb3cb325338edee11d182011060c624f5a3ee19d792a23",
   "gcr.io/fuzzbench/builders/eclipser/vorbis-2017-12-11":"sha256:c698b31fecda473d8560f606a3cc6fb42be432d4eae684e91009817ec3b9ba85",
   "gcr.io/fuzzbench/runners/eclipser/vorbis-2017-12-11-intermediate":"sha256:cb060d489dda15d50bf7be8e19bfc586dc5dbe03cb5c1110b00d6fbabceb15e2",
   "gcr.io/fuzzbench/runners/eclipser/vorbis-2017-12-11":"sha256:daae9e1a31b38120e75ed93ae9b8272de0d9a5215d2c6c117c65114ab1acab4e"
}


def _get_benchmark_fuzz_target(benchmarks):
    """Returns benchmark variables from benchmark.yaml files."""
    variables = ''
    for benchmark in benchmarks:
        benchmark_vars = yaml_utils.read(
            os.path.join(BENCHMARK_DIR, benchmark, 'benchmark.yaml'))
        variables += (benchmark + '-fuzz-target=' +
                      benchmark_vars['fuzz_target'] + '\n')
        variables += '\n'
    return variables


def _get_makefile_run_template(image):
    fuzzer = image['fuzzer']
    benchmark = image['benchmark']
    section = ''

    run_types = ['run', 'debug', 'test-run', 'debug-builder']
    testcases_dir = os.path.join(BENCHMARK_DIR, benchmark, 'testcases')
    if os.path.exists(testcases_dir):
        run_types.append('repro-bugs')

    for run_type in run_types:
        if run_type == 'debug-builder':
            section += f'{run_type}-{fuzzer}-{benchmark}: '
            section += f'.{fuzzer}-{benchmark}-builder-debug\n'
        else:
            section += f'{run_type}-{fuzzer}-{benchmark}: '
            section += f'.{fuzzer}-{benchmark}-runner\n'

        section += f'\
\tdocker run \\\n\
\t--cpus=1 \\\n\
\t--shm-size=2g \\\n\
\t--cap-add SYS_NICE \\\n\
\t--cap-add SYS_PTRACE \\\n\
\t-e FUZZ_OUTSIDE_EXPERIMENT=1 \\\n\
\t-e FORCE_LOCAL=1 \\\n\
\t-e TRIAL_ID=1 \\\n\
\t-e FUZZER={fuzzer} \\\n\
\t-e BENCHMARK={benchmark} \\\n\
\t-e FUZZ_TARGET=$({benchmark}-fuzz-target) \\\
\n'

        if run_type == 'test-run':
            section += '\t-e MAX_TOTAL_TIME=20 \\\n\t-e SNAPSHOT_PERIOD=10 \\\n'
        if run_type == 'debug-builder':
            section += '\t-e DEBUG_BUILDER=1 \\\n'
            section += '\t--entrypoint "/bin/bash" \\\n\t-it '
        elif run_type == 'debug':
            section += '\t--entrypoint "/bin/bash" \\\n\t-it '
        elif run_type == 'repro-bugs':
            section += f'\t-v {testcases_dir}:/testcases \\\n\t'
            section += '--entrypoint /bin/bash '
            section += os.path.join(BASE_TAG, image['tag'])
            section += ' -c "for f in /testcases/*; do '
            section += 'echo _________________________________________; '
            section += 'echo \\$$f:; '
            section += '\\$$OUT/\\$$FUZZ_TARGET -timeout=25 -rss_limit_mb=2560 '
            section += '\\$$f; done;" '
            section += '\n\n'
            continue
        elif run_type == 'run':
            section += '\t-it '
        else:
            section += '\t'

        if run_type != 'debug-builder':
            section += os.path.join(BASE_TAG, image['tag'])
        else:
            section += os.path.join(
                BASE_TAG, image['tag'].replace('runners/', 'builders/', 1))
        section += '\n\n'
    return section


def get_rules_for_image(name, image):
    image_name = "gcr.io/fuzzbench/" + image['tag']
    digest = ""
    if image_name in IMAGES_DIGEST:
        digest = "@" + IMAGES_DIGEST[image_name]

    """Returns makefile section for |image|."""
    if not ('base-' in name or 'dispatcher-' in name or name == 'worker'):
        section = '.'
    else:
        section = ''
    section += name + ':'
    if 'depends_on' in image:
        for dep in image['depends_on']:
            if 'base' in dep:
                section += ' ' + dep
            else:
                section += ' .' + dep
    section += '\n'
    if 'base-' in name:
        section += '\tdocker pull ubuntu:xenial\n'
    section += '\tdocker build \\\n'
    section += '\t--tag ' + os.path.join(BASE_TAG, image['tag']) + ' \\\n'
    section += '\t--build-arg BUILDKIT_INLINE_CACHE=1 \\\n'
    section += ('\t--cache-from ' + os.path.join(BASE_TAG, image['tag']) + digest +
                ' \\\n')

    if 'build_arg' in image:
        for arg in image['build_arg']:
            section += '\t--build-arg ' + arg + ' \\\n'
    if 'dockerfile' in image:
        section += '\t--file ' + image['dockerfile'] + ' \\\n'
    section += '\t' + image['context'] + '\n'
    section += '\n'

    # Print run, debug, test-run and debug-builder rules if image is a runner.
    if 'runner' in name and not ('intermediate' in name or 'base' in name):
        section += _get_makefile_run_template(image)
    return section


def main():
    """Writes Makefile with docker image build rules to sys.argv[1]."""
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} <makefile>')
        return 1
    makefile_path = sys.argv[1]
    makefile_contents = generate_makefile()
    with open(makefile_path, 'w') as file_handle:
        file_handle.write(makefile_contents)
    return 0


def generate_makefile():
    """Generates the contents of the makefile and returns it."""
    fuzzers = fuzzer_utils.get_fuzzer_names()
    benchmarks = benchmark_utils.get_all_benchmarks()
    buildable_images = docker_images.get_images_to_build(fuzzers, benchmarks)

    makefile = 'export DOCKER_BUILDKIT := 1\n\n'

    # Print oss-fuzz benchmarks property variables.
    makefile += _get_benchmark_fuzz_target(benchmarks)

    for name, image in buildable_images.items():
        makefile += get_rules_for_image(name, image)

    # Print build targets for all fuzzer-benchmark pairs (including coverage).
    fuzzers.append('coverage')
    for fuzzer in fuzzers:
        image_type = 'runner'
        if 'coverage' in fuzzer:
            image_type = 'builder'
        for benchmark in benchmarks:
            makefile += (f'build-{fuzzer}-{benchmark}: ' +
                         f'.{fuzzer}-{benchmark}-{image_type}\n')
        makefile += '\n'

    # Print fuzzer-all benchmarks build targets.
    for fuzzer in fuzzers:
        all_build_targets = ' '.join(
            [f'build-{fuzzer}-{benchmark}' for benchmark in benchmarks])
        makefile += f'build-{fuzzer}-all: {all_build_targets}\n'
        all_test_run_targets = ' '.join(
            [f'test-run-{fuzzer}-{benchmark}' for benchmark in benchmarks])
        makefile += f'test-run-{fuzzer}-all: {all_test_run_targets}\n'

    # Print all targets build target.
    all_build_targets = ' '.join([f'build-{fuzzer}-all' for fuzzer in fuzzers])
    makefile += f'build-all: {all_build_targets}'
    return makefile


if __name__ == '__main__':
    sys.exit(main())
