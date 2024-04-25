defmodule :m_dialyzer_coordinator do
  use Bitwise
  require Record

  Record.defrecord(:r_state, :state,
    mode: :undefined,
    active: 0,
    result: :undefined,
    next_label: 0,
    jobs: :undefined,
    job_fun: :undefined,
    init_data: :undefined,
    regulator: :undefined,
    job_labels_to_pid: :undefined
  )

  Record.defrecord(:r_plt_info, :plt_info,
    files: :undefined,
    mod_deps: :dict.new()
  )

  Record.defrecord(:r_iplt_info, :iplt_info,
    files: :undefined,
    mod_deps: :dict.new(),
    warning_map: :none,
    legal_warnings: :none
  )

  Record.defrecord(:r_plt, :plt,
    info: :undefined,
    types: :undefined,
    contracts: :undefined,
    callbacks: :undefined,
    exported_types: :undefined
  )

  Record.defrecord(:r_analysis, :analysis,
    analysis_pid: :undefined,
    type: :succ_typings,
    defines: [],
    doc_plt: :undefined,
    files: [],
    include_dirs: [],
    start_from: :byte_code,
    plt: :undefined,
    use_contracts: true,
    behaviours_chk: false,
    timing: false,
    timing_server: :none,
    callgraph_file: ~c"",
    mod_deps_file: ~c"",
    solvers: :undefined
  )

  Record.defrecord(:r_options, :options,
    files: [],
    files_rec: [],
    warning_files: [],
    warning_files_rec: [],
    analysis_type: :succ_typings,
    timing: false,
    defines: [],
    from: :byte_code,
    get_warnings: :maybe,
    init_plts: [],
    include_dirs: [],
    output_plt: :none,
    legal_warnings: :ordsets.new(),
    report_mode: :normal,
    erlang_mode: false,
    use_contracts: true,
    output_file: :none,
    output_format: :formatted,
    filename_opt: :basename,
    indent_opt: true,
    callgraph_file: ~c"",
    mod_deps_file: ~c"",
    check_plt: true,
    error_location: :column,
    metrics_file: :none,
    module_lookup_file: :none,
    solvers: []
  )

  Record.defrecord(:r_contract, :contract, contracts: [], args: [], forms: [])

  def parallel_job(mode, jobs, initData, timing) do
    state = spawn_jobs(mode, jobs, initData, timing)
    collect_result(state)
  end

  def wait_for_success_typings(
        labels,
        {_Collector, _Regulator, jobLabelsToPid}
      ) do
    f = fn jobLabel ->
      case :ets.lookup_element(jobLabelsToPid, jobLabel, 2, :ok) do
        pid when is_pid(pid) ->
          ref = :erlang.monitor(:process, pid)

          receive do
            {:DOWN, ^ref, :process, ^pid, _Info} ->
              :ok
          end

        :ok ->
          :ok
      end
    end

    :lists.foreach(f, labels)
  end

  defp spawn_jobs(mode, jobs, initData, timing) do
    collector = self()
    regulator = spawn_regulator()

    jobLabelsToPid =
      cond do
        mode === :typesig or mode === :dataflow ->
          :ets.new(
            :job_labels_to_pid,
            [{:read_concurrency, true}]
          )

        true ->
          :none
      end

    coordinator = {collector, regulator, jobLabelsToPid}
    jobFun = job_fun(jobLabelsToPid, mode, initData, coordinator)
    maxNumberOfInitJobs = 20 * :dialyzer_utils.parallelism()
    restJobs = launch_jobs(jobs, jobFun, maxNumberOfInitJobs)

    unit =
      case mode do
        :typesig ->
          ~c"SCCs"

        _ ->
          ~c"modules"
      end

    jobCount = length(jobs)
    :dialyzer_timing.send_size_info(timing, jobCount, unit)

    initResult =
      case mode do
        :compile ->
          :dialyzer_analysis_callgraph.compile_init_result()

        _ ->
          []
      end

    r_state(
      mode: mode,
      active: jobCount,
      result: initResult,
      next_label: 0,
      job_fun: jobFun,
      jobs: restJobs,
      init_data: initData,
      regulator: regulator,
      job_labels_to_pid: jobLabelsToPid
    )
  end

  defp launch_jobs(jobs, _JobFun, 0) do
    jobs
  end

  defp launch_jobs([job | jobs], jobFun, n) do
    jobFun.(job)
    launch_jobs(jobs, jobFun, n - 1)
  end

  defp launch_jobs([], _JobFun, _) do
    []
  end

  defp job_fun(:none, mode, initData, coordinator) do
    fn job ->
      _ = :dialyzer_worker.launch(mode, job, initData, coordinator)
      :ok
    end
  end

  defp job_fun(jobLabelsToPid, mode, initData, coordinator) do
    fn job ->
      jobLabel = get_job_label(mode, job)
      pid = :dialyzer_worker.launch(mode, job, initData, coordinator)
      true = :ets.insert(jobLabelsToPid, {jobLabel, pid})
      :ok
    end
  end

  defp collect_result(
         r_state(
           mode: mode,
           active: active,
           result: result,
           next_label: nextLabel,
           init_data: initData,
           jobs: jobsLeft,
           job_fun: jobFun,
           regulator: regulator,
           job_labels_to_pid: jobLabelsToPID
         ) = state
       ) do
    receive do
      {:next_label_request, estimation, pid} ->
        send(pid, {:next_label_reply, nextLabel})
        collect_result(r_state(state, next_label: nextLabel + estimation))

      {:done, job, data} ->
        newResult = update_result(mode, initData, job, data, result)

        case active do
          1 ->
            kill_regulator(regulator)

            case mode do
              :compile ->
                {newResult, nextLabel}

              _ ->
                cond do
                  jobLabelsToPID === :none ->
                    :ok

                  true ->
                    :ets.delete(jobLabelsToPID)
                end

                newResult
            end

          n ->
            cond do
              jobLabelsToPID === :none ->
                :ok

              true ->
                true =
                  :ets.delete(
                    jobLabelsToPID,
                    get_job_label(mode, job)
                  )
            end

            newJobsLeft =
              case jobsLeft do
                [] ->
                  []

                [newJob | jobsLeft1] ->
                  jobFun.(newJob)
                  jobsLeft1
              end

            newState = r_state(state, result: newResult, jobs: newJobsLeft, active: n - 1)
            collect_result(newState)
        end
    end
  end

  defp update_result(mode, initData, job, data, result) do
    cond do
      mode === :compile ->
        :dialyzer_analysis_callgraph.add_to_result(job, data, result, initData)

      mode === :typesig or mode === :dataflow ->
        :dialyzer_succ_typings.add_to_result(data, result, initData)

      true ->
        data ++ result
    end
  end

  def get_job_label(:typesig, {label, _Input}) do
    label
  end

  def get_job_label(:dataflow, job) do
    job
  end

  def get_job_label(:contract_remote_types, job) do
    job
  end

  def get_job_label(:record_remote_types, job) do
    job
  end

  def get_job_label(:warnings, job) do
    job
  end

  def get_job_label(:compile, job) do
    job
  end

  def get_job_input(:typesig, {_Label, input}) do
    input
  end

  def get_job_input(:dataflow, job) do
    job
  end

  def get_job_input(:contract_remote_types, job) do
    job
  end

  def get_job_input(:record_remote_types, job) do
    job
  end

  def get_job_input(:warnings, job) do
    job
  end

  def get_job_input(:compile, job) do
    job
  end

  def job_done(job, result, {collector, regulator, _JobLabelsToPID}) do
    send(regulator, :done)
    send(collector, {:done, job, result})
    :ok
  end

  def get_next_label(
        estimatedSize,
        {collector, _Regulator, _JobLabelsToPID}
      ) do
    send(collector, {:next_label_request, estimatedSize, self()})

    receive do
      {:next_label_reply, nextLabel} ->
        nextLabel
    end
  end

  defp wait_activation() do
    receive do
      :activate ->
        :ok
    end
  end

  defp activate_pid(pid) do
    send(pid, :activate)
  end

  def request_activation({_Collector, regulator, _JobLabelsToPID}) do
    send(regulator, {:req, self()})
    wait_activation()
  end

  defp spawn_regulator() do
    initTickets = :dialyzer_utils.parallelism()

    spawn_link(fn ->
      regulator_loop(initTickets, :queue.new())
    end)
  end

  defp regulator_loop(tickets, queue) do
    receive do
      {:req, pid} ->
        case tickets do
          0 ->
            regulator_loop(0, :queue.in(pid, queue))

          n ->
            activate_pid(pid)
            regulator_loop(n - 1, queue)
        end

      :done ->
        case :queue.out(queue) do
          {:empty, newQueue} ->
            regulator_loop(tickets + 1, newQueue)

          {{:value, pid}, newQueue} ->
            activate_pid(pid)
            regulator_loop(tickets, newQueue)
        end

      :stop ->
        :ok
    end
  end

  defp kill_regulator(regulator) do
    send(regulator, :stop)
  end
end
