local config = import 'default.jsonnet';

config {
  'cronos_777-1'+: {
    'start-flags': '--trace --unsafe-experimental --inv-check-period 5',
    'app-config'+: {
      'minimum-gas-prices':: super['minimum-gas-prices'],
      'json-rpc'+: {
        api:: super['api'],
      },
    },
    accounts: [{
      name: 'community',
      coins: '10000000000000000000000basetcro',
      mnemonic: '${COMMUNITY_MNEMONIC}',
    }],
    genesis+: {
      consensus_params:: super['consensus_params'],
      app_state+: {
        evm+: {
          accounts: [
            {
              address: '0x68542BD12B41F5D51D6282Ec7D91D7d0D78E4503',
              code: '608060405234801561001057600080fd5b50600436106100ea5760003560e01c806395d89b411161008c578063d3d78b9b11610066578063d3d78b9b146102cc578063dd62ed3e14610300578063e6711ef61461032e578063e978206414610336576100ea565b806395d89b411461026c578063a457c2d714610274578063a9059cbb146102a0576100ea565b806323b872dd116100c857806323b872dd146101c6578063313ce567146101fc578063395093511461021a57806370a0823114610246576100ea565b806306fdde03146100ef578063095ea7b31461016c57806318160ddd146101ac575b600080fd5b6100f7610362565b6040805160208082528351818301528351919283929083019185019080838360005b83811015610131578181015183820152602001610119565b50505050905090810190601f16801561015e5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b6101986004803603604081101561018257600080fd5b506001600160a01b0381351690602001356103f8565b604080519115158252519081900360200190f35b6101b4610415565b60408051918252519081900360200190f35b610198600480360360608110156101dc57600080fd5b506001600160a01b0381358116916020810135909116906040013561041b565b6102046104a8565b6040805160ff9092168252519081900360200190f35b6101986004803603604081101561023057600080fd5b506001600160a01b0381351690602001356104b1565b6101b46004803603602081101561025c57600080fd5b50356001600160a01b0316610505565b6100f7610520565b6101986004803603604081101561028a57600080fd5b506001600160a01b038135169060200135610581565b610198600480360360408110156102b657600080fd5b506001600160a01b0381351690602001356105ef565b6102fe600480360360608110156102e257600080fd5b506001600160a01b038135169060208101359060400135610603565b005b6101b46004803603604081101561031657600080fd5b506001600160a01b03813581169160200135166106ad565b6101b46106d8565b6102fe6004803603604081101561034c57600080fd5b506001600160a01b0381351690602001356106dd565b60038054604080516020601f60026000196101006001881615020190951694909404938401819004810282018101909252828152606093909290918301828280156103ee5780601f106103c3576101008083540402835291602001916103ee565b820191906000526020600020905b8154815290600101906020018083116103d157829003601f168201915b5050505050905090565b600061040c61040561070b565b848461070f565b50600192915050565b60025490565b60006104288484846107fb565b61049e8461043461070b565b61049985604051806060016040528060288152602001610d33602891396001600160a01b038a1660009081526001602052604081209061047261070b565b6001600160a01b03168152602081019190915260400160002054919063ffffffff61096216565b61070f565b5060019392505050565b60055460ff1690565b600061040c6104be61070b565b8461049985600160006104cf61070b565b6001600160a01b03908116825260208083019390935260409182016000908120918c16815292529020549063ffffffff6109f916565b6001600160a01b031660009081526020819052604090205490565b60048054604080516020601f60026000196101006001881615020190951694909404938401819004810282018101909252828152606093909290918301828280156103ee5780601f106103c3576101008083540402835291602001916103ee565b600061040c61058e61070b565b8461049985604051806060016040528060258152602001610dc560259139600160006105b861070b565b6001600160a01b03908116825260208083019390935260409182016000908120918d1681529252902054919063ffffffff61096216565b600061040c6105fc61070b565b84846107fb565b81810182811015610654576040805162461bcd60e51b8152602060048201526016602482015275736166652d6d6174682d6164642d6f766572666c6f7760501b604482015290519081900360640190fd5b61065e3382610a5a565b604080516001600160a01b03861681526020810185905280820184905290517f937492d2511a2fbc9b51ea08825f1e252247d339dfd50904ebf4f4411f1d81369181900360600190a150505050565b6001600160a01b03918216600090815260016020908152604080832093909416825291909152205490565b602a90565b337389a7ef2f08b1c018d5cc88836249b84dd5392905146106fd57600080fd5b6107078282610b62565b5050565b3390565b6001600160a01b0383166107545760405162461bcd60e51b8152600401808060200182810382526024815260200180610da16024913960400191505060405180910390fd5b6001600160a01b0382166107995760405162461bcd60e51b8152600401808060200182810382526022815260200180610ceb6022913960400191505060405180910390fd5b6001600160a01b03808416600081815260016020908152604080832094871680845294825291829020859055815185815291517f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b9259281900390910190a3505050565b6001600160a01b0383166108405760405162461bcd60e51b8152600401808060200182810382526025815260200180610d7c6025913960400191505060405180910390fd5b6001600160a01b0382166108855760405162461bcd60e51b8152600401808060200182810382526023815260200180610ca66023913960400191505060405180910390fd5b610890838383610c5e565b6108d381604051806060016040528060268152602001610d0d602691396001600160a01b038616600090815260208190526040902054919063ffffffff61096216565b6001600160a01b038085166000908152602081905260408082209390935590841681522054610908908263ffffffff6109f916565b6001600160a01b038084166000818152602081815260409182902094909455805185815290519193928716927fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef92918290030190a3505050565b600081848411156109f15760405162461bcd60e51b81526004018080602001828103825283818151815260200191508051906020019080838360005b838110156109b657818101518382015260200161099e565b50505050905090810190601f1680156109e35780820380516001836020036101000a031916815260200191505b509250505060405180910390fd5b505050900390565b600082820183811015610a53576040805162461bcd60e51b815260206004820152601b60248201527f536166654d6174683a206164646974696f6e206f766572666c6f770000000000604482015290519081900360640190fd5b9392505050565b6001600160a01b038216610a9f5760405162461bcd60e51b8152600401808060200182810382526021815260200180610d5b6021913960400191505060405180910390fd5b610aab82600083610c5e565b610aee81604051806060016040528060228152602001610cc9602291396001600160a01b038516600090815260208190526040902054919063ffffffff61096216565b6001600160a01b038316600090815260208190526040902055600254610b1a908263ffffffff610c6316565b6002556040805182815290516000916001600160a01b038516917fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef9181900360200190a35050565b6001600160a01b038216610bbd576040805162461bcd60e51b815260206004820152601f60248201527f45524332303a206d696e7420746f20746865207a65726f206164647265737300604482015290519081900360640190fd5b610bc960008383610c5e565b600254610bdc908263ffffffff6109f916565b6002556001600160a01b038216600090815260208190526040902054610c08908263ffffffff6109f916565b6001600160a01b0383166000818152602081815260408083209490945583518581529351929391927fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef9281900390910190a35050565b505050565b6000610a5383836040518060400160405280601e81526020017f536166654d6174683a207375627472616374696f6e206f766572666c6f77000081525061096256fe45524332303a207472616e7366657220746f20746865207a65726f206164647265737345524332303a206275726e20616d6f756e7420657863656564732062616c616e636545524332303a20617070726f766520746f20746865207a65726f206164647265737345524332303a207472616e7366657220616d6f756e7420657863656564732062616c616e636545524332303a207472616e7366657220616d6f756e74206578636565647320616c6c6f77616e636545524332303a206275726e2066726f6d20746865207a65726f206164647265737345524332303a207472616e736665722066726f6d20746865207a65726f206164647265737345524332303a20617070726f76652066726f6d20746865207a65726f206164647265737345524332303a2064656372656173656420616c6c6f77616e63652062656c6f77207a65726fa26469706673582212203ad18e3c8894a8cb3aa50316961c792e96a3dfb497a816e09208ce0d7d83fe1364736f6c63430006060033',
              storage: [
                {
                  key: '0x0000000000000000000000000000000000000000000000000000000000000002',
                  value: '0x00000000000000000000000000000000000000000052b7d2dcc80cd2e4000000',
                },
                {
                  key: '0x0000000000000000000000000000000000000000000000000000000000000003',
                  value: '0x46616e637900000000000000000000000000000000000000000000000000000a',
                },
                {
                  key: '0x0000000000000000000000000000000000000000000000000000000000000004',
                  value: '0x464e590000000000000000000000000000000000000000000000000000000006',
                },
                {
                  key: '0x0000000000000000000000000000000000000000000000000000000000000005',
                  value: '0x0000000000000000000000000000000000000000000000000000000000000012',
                },
                {
                  key: '0xfdf316244ccb1f71d092e0b583c1d6ca63792a4f14f6a78c698707836bd6823e',
                  value: '0x00000000000000000000000000000000000000000052b7d2dcc80cd2e4000000',
                },
              ],
            },
          ],
        },
        cronos+: {
          params: {
            enable_auto_deployment: true,
          },
          external_contracts: [
            {
              denom: 'gravity0x0000000000000000000000000000000000000000',
              contract: '0x68542BD12B41F5D51D6282Ec7D91D7d0D78E4503',
            },
          ],
          auto_contracts: [
            {
              denom: 'gravity0x0000000000000000000000000000000000000000',
              contract: '0x68542BD12B41F5D51D6282Ec7D91D7d0D78E4503',
            },
          ],
        },
        auth+: {
          accounts: [
            {
              '@type': '/ethermint.types.v1.EthAccount',
              base_account: {
                address: 'crc1dp2zh5ftg86a28tzstk8mywh6rtcu3gr08l7s9',
                sequence: '1',
              },
              code_hash: '0x02729233449ce9cb69aa3b872baba2b5b2257e179efe2f3365b4cf443ebde102',
            },
          ],
        },
        feemarket: {
          params: {
            no_base_fee: true,
          },
        },
        gov:: super['gov'],
        transfer:: super['transfer'],
      },
    },
  },
}
