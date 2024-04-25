defmodule :m_dialyzer_typegraph do
  use Bitwise
  require Record
  Record.defrecord(:r_plt_info, :plt_info, files: :undefined,
                                    mod_deps: :dict.new())
  Record.defrecord(:r_iplt_info, :iplt_info, files: :undefined,
                                     mod_deps: :dict.new(), warning_map: :none,
                                     legal_warnings: :none)
  Record.defrecord(:r_plt, :plt, info: :undefined,
                               types: :undefined, contracts: :undefined,
                               callbacks: :undefined,
                               exported_types: :undefined)
  Record.defrecord(:r_analysis, :analysis, analysis_pid: :undefined,
                                    type: :succ_typings, defines: [],
                                    doc_plt: :undefined, files: [],
                                    include_dirs: [], start_from: :byte_code,
                                    plt: :undefined, use_contracts: true,
                                    behaviours_chk: false, timing: false,
                                    timing_server: :none, callgraph_file: '',
                                    mod_deps_file: '', solvers: :undefined)
  Record.defrecord(:r_options, :options, files: [], files_rec: [],
                                   warning_files: [], warning_files_rec: [],
                                   analysis_type: :succ_typings, timing: false,
                                   defines: [], from: :byte_code,
                                   get_warnings: :maybe, init_plts: [],
                                   include_dirs: [], output_plt: :none,
                                   legal_warnings: :ordsets.new(),
                                   report_mode: :normal, erlang_mode: false,
                                   use_contracts: true, output_file: :none,
                                   output_format: :formatted,
                                   filename_opt: :basename, indent_opt: true,
                                   callgraph_file: '', mod_deps_file: '',
                                   check_plt: true, error_location: :column,
                                   metrics_file: :none,
                                   module_lookup_file: :none, solvers: [])
  Record.defrecord(:r_contract, :contract, contracts: [], args: [],
                                    forms: [])
  defp get_behaviours_for_module(m, codeServer) do
    modCode = :dialyzer_codeserver.lookup_mod_code(m,
                                                     codeServer)
    attrs = :cerl.module_attrs(modCode)
    {behaviours,
       _BehaviourLocations} = :dialyzer_behaviours.get_behaviours(attrs)
    behaviours
  end

  defp module_type_deps_of_contract(r_contract(forms: forms)) do
    typeForms = (for {typeForm, _Constraints} <- forms do
                   typeForm
                 end)
    constraintForms = :lists.append(for {_TypeForm,
                                           constraints} <- forms do
                                      constraints
                                    end)
    :lists.usort(:lists.append(:erl_types.type_form_to_remote_modules(typeForms),
                                 :dialyzer_contracts.constraint_form_to_remote_modules(constraintForms)))
  end

end