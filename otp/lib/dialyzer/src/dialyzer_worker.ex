defmodule :m_dialyzer_worker do
  use Bitwise
  require Record

  Record.defrecord(:r_state, :state,
    mode: :undefined,
    job: :undefined,
    coordinator: :undefined,
    init_data: :undefined
  )

  def launch(mode, job, initData, coordinator) do
    state = r_state(mode: mode, job: job, init_data: initData, coordinator: coordinator)

    spawn_link(fn ->
      init(state)
    end)
  end

  defp init(r_state(job: job, mode: mode, init_data: initData) = state)
       when mode === :typesig or mode === :dataflow do
    wait_for_success_typings(mode, job, initData, state)
    run(state)
  end

  defp init(r_state(mode: mode) = state)
       when mode === :compile or
              mode === :warnings or
              mode === :contract_remote_types or
              mode === :record_remote_types do
    run(state)
  end

  defp run(
         r_state(
           coordinator: coordinator,
           job: job
         ) = state
       ) do
    :dialyzer_coordinator.request_activation(coordinator)
    result = run_job(state)
    :ok
    :dialyzer_coordinator.job_done(job, result, coordinator)
  end

  defp run_job(r_state(mode: mode, job: job, init_data: initData) = state) do
    :ok

    startableJob =
      :dialyzer_coordinator.get_job_input(
        mode,
        job
      )

    case mode do
      :compile ->
        case start_compilation(state) do
          {:ok, estimatedSize, data} ->
            label = ask_coordinator_for_label(estimatedSize, state)
            continue_compilation(label, data)

          {:error, _Reason} = error ->
            error
        end

      _ ->
        ^startableJob =
          :dialyzer_coordinator.get_job_input(
            mode,
            job
          )

        case mode do
          :typesig ->
            :dialyzer_succ_typings.find_succ_types_for_scc(
              startableJob,
              initData
            )

          :dataflow ->
            :dialyzer_succ_typings.refine_one_module(
              startableJob,
              initData
            )

          :contract_remote_types ->
            :dialyzer_contracts.process_contract_remote_types_module(
              startableJob,
              initData
            )

          :record_remote_types ->
            :dialyzer_utils.process_record_remote_types_module(
              startableJob,
              initData
            )

          :warnings ->
            :dialyzer_succ_typings.collect_warnings(
              startableJob,
              initData
            )
        end
    end
  end

  defp start_compilation(r_state(job: job, init_data: initData)) do
    :dialyzer_analysis_callgraph.start_compilation(
      job,
      initData
    )
  end

  defp ask_coordinator_for_label(estimatedSize, r_state(coordinator: coordinator)) do
    :dialyzer_coordinator.get_next_label(
      estimatedSize,
      coordinator
    )
  end

  defp continue_compilation(label, data) do
    :dialyzer_analysis_callgraph.continue_compilation(
      label,
      data
    )
  end

  defp wait_for_success_typings(mode, job, initData, r_state(coordinator: coordinator)) do
    jobLabel =
      :dialyzer_coordinator.get_job_label(
        mode,
        job
      )

    dependsOnJobLabels =
      :dialyzer_succ_typings.find_depends_on(
        jobLabel,
        initData
      )

    :ok

    :dialyzer_coordinator.wait_for_success_typings(
      dependsOnJobLabels,
      coordinator
    )
  end
end
