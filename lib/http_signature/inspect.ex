defmodule HTTPSignature.Inspect do
  import Inspect.Algebra, only: [
    color: 3,
    concat: 2,
    surround_many: 6,
    to_doc: 2
  ]

  def inspect(%{__struct__: struct} = map, opts) do
    pruned = :maps.remove(:__struct__, map)
    pruned = :lists.sort(:maps.to_list(pruned))
    colorless_opts = %{opts | syntax_colors: []}
    name = Inspect.Atom.inspect(struct, colorless_opts)
    open = color("%" <> name <> "{", :map, opts)
    sep = color(",", :map, opts)
    close = color("}", :map, opts)
    surround_many(open, pruned, close, opts, traverse_fun(pruned), sep)
  end

  @doc false
  defp traverse_fun(list) do
    if Inspect.List.keyword?(list) do
      &Inspect.List.keyword/2
    else
      &to_map/2
    end
  end

  @doc false
  defp to_map({key, value}, opts) do
    concat(
      concat(to_doc(key, opts), " => "),
      to_doc(value, opts)
    )
  end
end

defimpl Inspect, for: [:http_signature_authorization, :http_signature_key, :http_signature_request, :http_signature_signer, :http_signature_verifier] do
  defdelegate inspect(struct, opts), to: HTTPSignature.Inspect
end
