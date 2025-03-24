export default function SpinnerModal() {
    return (<>
      <div className="fixed inset-0 z-10 m-auto opacity-50">
        <div
          className={`h-20 w-20 animate-spin rounded-full border-4 border-gray-600 border-t-transparent absolute inset-0 z-20 m-auto`}
        />
      </div>
    </>)
}
  