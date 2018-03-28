#include <map>
#include <set>
#include <string>

#define STRINGIFY2(x) #x
#define STRINGIFY(x) STRINGIFY2(x)

#define LOAD_SYMBOL(plugin, symbol)                                            \
  dlerror();                                                                   \
  decltype(&symbol) symbol =                                                   \
      (decltype(symbol))dlsym(plugin, STRINGIFY(symbol));                      \
  {                                                                            \
    const char *err = NULL;                                                    \
    if ((err = dlerror())) {                                                   \
      std::cout << "Error loading symbol: " << err << std::endl;               \
      exit(-1);                                                                \
    }                                                                          \
    assert(symbol && "Error loading symbol.");                                 \
  }

extern "C" {
/**
 * Allows the contract to perform any initialization necessary.
 */
void contract_init();

/**
 * Gets the list of user-defined variables that the contract exports. Returns an
 * empty list if no user variables are to be exported
 * @param function_name The name of the function to look up.
 * @returns A map associating each variable name to its worst-case value.
 */
std::map<std::string, std::string>
contract_get_user_variables(std::string function_name);

/**
 * Check whether a given function is covered by a contract.
 *
 * @param function_name The name of the function to check.
 * @returns true iff the function has a contract.
 */
bool contract_has_contract(std::string function_name);

/**
 * Gets the set of optimization variables that the contact exports as well as
 * their candidate values.
 *
 * @param function_name The name of the function to look up.
 * @returns A map associating each variable name to a set of candidate values.
 */
std::map<std::string, std::set<std::string>>
contract_get_optimization_variables(std::string function_name);

/**
 * Gets the number of subcontracts (mutually exclusive scenarios that partition
 * the input space for the contract).
 *
 * @param function_name The name of the function to look up.
 * @returns The number of subcontracts.
 */
int contract_num_sub_contracts(std::string function_name);

/**
 * Gets the set of constraints that must hold for a given subcontract to apply.
 *
 * @param function_name The name of the contract function.
 * @param sub_contract_idx The sub contract index.
 * @returns The set of constraints written as an SMT expression string.
 */
std::string contract_get_subcontract_constraints(std::string function_name,
                                                 int sub_contract_idx);

/**
 * Computes the bound on the number of CPU cycles for the given subcontract.
 *
 * @param function_name The name of the contract function.
 * @param sub_contract_idx The sub contract index.
 * @param variables The assignment for all user-defined and optimization
 * variables.
 * @returns The computed CPU cycle bound.
 */
int contract_get_sub_contract_performance(
    std::string function_name, int sub_contract_idx,
    std::map<std::string, long> variables);
}
